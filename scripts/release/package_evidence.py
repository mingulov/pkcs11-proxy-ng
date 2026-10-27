"""Fail-closed candidate-evidence and release-asset identity checks.

Stage C (Task 5b) helper behind the ``candidate-name``,
``evidence-select``, ``assets-compare``, ``manifest-compatible``, and
``tag-evidence`` subcommands of ``scripts/release_checks.py``. Every
function raises :class:`ReleaseError` on any mismatch; callers treat
a nonzero exit as a hard refusal, never a fallback.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import time

from .package_model import ReleaseError, require


SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
RUN_ID = re.compile(r"[1-9][0-9]*\Z")

def candidate_name(tag_commit: str, run_id: str) -> str:
    require(isinstance(tag_commit, str) and SHA40.match(tag_commit) is not None,
            f"tag commit {tag_commit!r} is not a 40-hex SHA")
    require(isinstance(run_id, str) and RUN_ID.match(run_id) is not None,
            f"run id {run_id!r} is not a positive integer")
    return f"crates-candidate-{tag_commit}-{run_id}"


def _expired(record: dict, now: float) -> bool:
    if record.get("expired", False):
        return True
    expires_at = record.get("expires_at")
    require(isinstance(expires_at, str) and bool(expires_at),
            f"artifact {record.get('name')!r} carries no expiry evidence")
    try:
        stamp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReleaseError(f"artifact {record.get('name')!r} expiry "
                           f"{expires_at!r} is invalid: {exc}") from exc
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.timestamp() <= now


def select_evidence(runs_path: Path, run_id: str, repository: str,
                    workflow: str, event: str, name: str,
                    now: float | None = None,
                    head_sha: str | None = None) -> dict:
    # No head_sha criterion: the publish run is dispatched from main
    # (the tag's frozen workflow predates fixes), so its head names
    # the workflow version, never the tag commit. The parameter stays
    # (ignored) so one workflow serves pre-fix tag scripts, which
    # require the flag with the run's own head.
    _ = head_sha
    try:
        payload = json.loads(Path(runs_path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise ReleaseError(f"cannot read runs listing {runs_path}: {exc}") from exc
    runs = payload.get("runs")
    require(isinstance(runs, list), "runs listing must contain a runs list")
    moment = time.time() if now is None else now
    matches = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        if (str(run.get("id")) != str(run_id)
                or run.get("repository") != repository
                or run.get("workflow_path") != workflow
                or run.get("event") != event):
            continue
        for artifact in run.get("artifacts", []):
            if not isinstance(artifact, dict) or artifact.get("name") != name:
                continue
            if _expired(artifact, moment):
                continue
            matches.append({"run_id": run.get("id"), **artifact})
    require(len(matches) == 1,
            f"expected exactly one unexpired {name!r} artifact, "
            f"found {len(matches)}")
    return matches[0]


def _asset_map(records, path: Path) -> dict:
    require(isinstance(records, list), f"{path} must list assets")
    assets = {}
    for record in records:
        require(isinstance(record, dict), f"{path} asset entries must be objects")
        name = record.get("name")
        digest = record.get("sha256")
        require(isinstance(name, str) and bool(name),
                f"{path} asset name is invalid")
        require(isinstance(digest, str) and SHA64.match(digest) is not None,
                f"{path} asset {name!r} sha256 is invalid")
        require(name not in assets, f"{path} lists {name!r} twice")
        assets[name] = digest
    return assets


# Retired in 0.3.1: a retry of a pre-0.3.1 release keeps these on the
# release untouched, and the manifest check tolerates their absence
# from the prepared set. Anything else must match exactly.
LEGACY_MANIFEST_NAMES = frozenset({
    "qualification-binding.json",
    "qualification-record.json",
    "qualification-receipt.json",
    "qualification-evidence.tar.gz",
})


def manifests_match_ignoring_legacy(existing_path: Path,
                                    prepared_path: Path) -> dict:
    try:
        existing_raw = json.loads(Path(existing_path).read_text(encoding="utf-8"))
        prepared_raw = json.loads(Path(prepared_path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise ReleaseError(f"cannot read asset listings: {exc}") from exc
    existing = _asset_map(existing_raw, existing_path)
    prepared = _asset_map(prepared_raw, prepared_path)
    # Only existing-only legacy names are tolerated: prepared-only
    # entries (legacy or not) mean the release lacks staged files,
    # and shared names — legacy included — must pin identical bytes.
    # Comparison is on (name, sha256) only: the `path` field is
    # build-local metadata whose format varies across tag vintages.
    prepared_only = sorted(set(prepared) - set(existing))
    require(not prepared_only,
            f"prepared manifest lists {prepared_only} missing from the "
            "released assets.json; refusing to replace")
    existing_only = sorted(set(existing) - set(prepared))
    non_legacy = [name for name in existing_only
                  if name not in LEGACY_MANIFEST_NAMES]
    require(not non_legacy,
            f"released assets.json lists {non_legacy} missing from the "
            "prepared manifest; refusing to replace")
    for name in sorted(set(existing) & set(prepared)):
        require(existing[name] == prepared[name],
                f"existing asset {name!r} diverges: released "
                f"{existing[name]} differs from prepared "
                f"{prepared[name]}; refusing to replace")
    return {"match": True, "compared": sorted(prepared),
            "tolerated_legacy": sorted(set(existing_only)
                                       & set(LEGACY_MANIFEST_NAMES))}


def compare_assets(existing_path: Path, prepared_path: Path) -> dict:
    try:
        existing_raw = json.loads(Path(existing_path).read_text(encoding="utf-8"))
        prepared_raw = json.loads(Path(prepared_path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise ReleaseError(f"cannot read asset listings: {exc}") from exc
    existing = _asset_map(existing_raw, existing_path)
    prepared = _asset_map(prepared_raw, prepared_path)
    retain, add = [], []
    for name, digest in sorted(prepared.items()):
        if name not in existing:
            add.append(name)
        elif existing[name] == digest:
            retain.append(name)
        else:
            raise ReleaseError(
                f"existing asset {name!r} diverges: released {existing[name]} "
                f"differs from prepared {digest}; refusing to replace")
    return {"retain": retain, "add": add}


def tag_evidence(repo: Path, tag: str, expect_peeled: str | None = None) -> dict:
    repo = Path(repo)
    try:
        obj = subprocess.run(["git", "rev-parse", f"{tag}^{{object}}"],
                             cwd=repo, text=True, capture_output=True,
                             check=True).stdout.strip()
        kind = subprocess.run(["git", "cat-file", "-t", obj],
                              cwd=repo, text=True, capture_output=True,
                              check=True).stdout.strip()
        peeled = subprocess.run(["git", "rev-parse", f"{tag}^{{}}"],
                                cwd=repo, text=True, capture_output=True,
                                check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ReleaseError(f"cannot resolve tag {tag!r}: {exc}") from exc
    require(kind == "tag",
            f"tag {tag!r} resolves to a {kind} object, not an annotated tag")
    require(SHA40.match(obj) is not None and SHA40.match(peeled) is not None,
            f"tag {tag!r} object evidence is invalid")
    if expect_peeled is not None:
        require(peeled == expect_peeled,
                f"tag {tag!r} peels to {peeled}, expected {expect_peeled}")
    return {"tag": tag, "object": obj, "peeled": peeled}

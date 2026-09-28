"""Fail-closed candidate-evidence and release-asset identity checks.

Stage C (Task 5b) helper behind the ``candidate-name``, ``evidence-bind``,
``evidence-verify``, ``evidence-select``, ``assets-compare``, and
``tag-evidence`` subcommands of ``scripts/release_checks.py``. Every
function raises :class:`ReleaseError` on any mismatch; callers treat a
nonzero exit as a hard refusal, never a fallback.
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


def write_binding(output: Path, tag_commit: str, run_id: str,
                  qualification_url: str, qualification_subject: str) -> dict:
    require(isinstance(qualification_url, str) and
            qualification_url.startswith("https://"),
            "qualification URL must use https")
    require(isinstance(qualification_subject, str) and
            SHA40.match(qualification_subject) is not None,
            "qualification subject must be a 40-hex SHA")
    binding = {"format_version": 1,
               "artifact": candidate_name(tag_commit, run_id),
               "tag_commit": tag_commit,
               "run_id": run_id,
               "qualification_url": qualification_url,
               "qualification_subject": qualification_subject}
    try:
        Path(output).write_text(json.dumps(binding, indent=2, sort_keys=True)
                                + "\n", encoding="utf-8")
    except OSError as exc:
        raise ReleaseError(f"cannot write binding {output}: {exc}") from exc
    return binding


def read_binding(path: Path) -> dict:
    try:
        binding = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise ReleaseError(f"cannot read evidence binding {path}: {exc}") from exc
    require(isinstance(binding, dict) and binding.get("format_version") == 1,
            f"evidence binding {path} has an invalid format")
    return binding


def verify_binding(path: Path, expect_url: str, expect_subject: str,
                   expect_tag_commit: str, expect_run_id: str | None = None) -> dict:
    binding = read_binding(path)
    for key, expected in (("qualification_url", expect_url),
                          ("qualification_subject", expect_subject),
                          ("tag_commit", expect_tag_commit)):
        require(binding.get(key) == expected,
                f"evidence binding {key} {binding.get(key)!r} "
                f"does not match expected {expected!r}")
    if expect_run_id is not None:
        require(str(binding.get("run_id")) == str(expect_run_id),
                f"evidence binding run_id {binding.get('run_id')!r} "
                f"does not match expected {expect_run_id!r}")
    return binding


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
    # the workflow version, never the tag commit. Tag binding comes
    # from the artifact name plus evidence-verify downstream. The
    # parameter stays (ignored) so one workflow serves pre-fix tag
    # scripts, which require the flag with the run's own head.
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

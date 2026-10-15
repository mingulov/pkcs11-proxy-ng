"""Source, ref, and qualification gates shared by publication workflows."""

from pathlib import Path
import json
import re
import subprocess
from urllib.parse import urlsplit

from .package_model import PACKAGES, ReleaseError, checked_workspace, git, require


STABLE_REF = re.compile(r"refs/tags/v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))\Z")
HEX_SHA = re.compile(r"[0-9a-f]{40,64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
QUAL_RUN_ID = re.compile(r"[1-9][0-9]*\Z")
MODES = ("dry-run", "bootstrap", "trusted")
PACKAGE_NAMES = ("workspace", *(name for name, _ in PACKAGES))


def qualification_url(url: str) -> bool:
    if not url or any(char.isspace() or ord(char) < 32 for char in url) or "\\" in url:
        return False
    try:
        parsed = urlsplit(url)
        return (parsed.scheme == "https" and bool(parsed.hostname) and
                parsed.username is None and parsed.password is None and
                (parsed.port is None or parsed.port > 0) and not parsed.fragment)
    except ValueError:
        return False


def preflight(repo: Path, ref: str, require_main: bool, mode: str,
              package: str, qualification_subject: str | None,
              qualification_url_value: str | None,
              qualification_run_id: str | None = None,
              qualification_framework: str | None = None,
              qualification_record_sha256: str | None = None,
              qualification_receipt_sha256: str | None = None,
              ) -> tuple[str, str, str]:
    match = STABLE_REF.fullmatch(ref)
    require(match is not None, "ref must be a full stable refs/tags/vMAJOR.MINOR.PATCH")
    require(mode in MODES, f"invalid publication mode: {mode}")
    require(package in PACKAGE_NAMES, f"unknown release package: {package}")
    if mode != "dry-run":
        require(require_main, "upload mode requires origin/main ancestry check")
    version = checked_workspace(repo)
    require(version == match.group(1), f"tag version {match.group(1)} differs from workspace {version}")
    require(git(repo, "cat-file", "-t", ref) == "tag", "release ref must be an annotated tag")
    tag_headers = git(repo, "cat-file", "-p", ref).split("\n\n", 1)[0].splitlines()
    require([line for line in tag_headers if line.startswith("tag ")] ==
            ["tag " + ref.removeprefix("refs/tags/")],
            "annotated tag object's name differs from release ref")
    tag_commit = git(repo, "rev-parse", "--verify", ref + "^{commit}")
    head = git(repo, "rev-parse", "HEAD")
    require(tag_commit == head, "release tag must point to checked-out HEAD")
    require(not git(repo, "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"),
            "release checkout must be clean")
    frozen_parent = git(repo, "rev-parse", "HEAD~1")
    if require_main:
        ancestor = subprocess.run(["git", "merge-base", "--is-ancestor", head,
                                   "refs/remotes/origin/main"], cwd=repo, capture_output=True)
        require(ancestor.returncode == 0, "release tag is not on origin/main ancestry")
    receipt = Path(__file__).resolve().parents[1] / "verify-quality-receipt.sh"
    result = subprocess.run([str(receipt), ref.removeprefix("refs/tags/")],
                            cwd=repo, text=True, capture_output=True)
    require(result.returncode == 0, f"quality receipt refused: {result.stderr.strip()}")
    qual_identity = (qualification_run_id, qualification_framework,
                     qualification_record_sha256,
                     qualification_receipt_sha256)
    if mode != "dry-run":
        require(qualification_subject is not None and qualification_url_value is not None
                and all(value is not None for value in qual_identity),
                "upload mode requires qualification subject, URL, run id, "
                "framework, and record/receipt digests")
    if qualification_subject is not None or qualification_url_value is not None:
        require(qualification_subject is not None and HEX_SHA.fullmatch(qualification_subject) is not None and
                qualification_subject == frozen_parent, "qualification subject must equal frozen parent SHA")
        require(qualification_url_value is not None and qualification_url(qualification_url_value),
                "qualification URL must be credential-free HTTPS with a host")
    if qualification_run_id is not None:
        require(QUAL_RUN_ID.fullmatch(qualification_run_id) is not None,
                "qualification run id must be a positive integer")
    if qualification_framework is not None:
        require(HEX40.fullmatch(qualification_framework) is not None,
                "qualification framework must be a 40-hex SHA")
    if qualification_record_sha256 is not None:
        require(HEX64.fullmatch(qualification_record_sha256) is not None,
                "qualification record sha256 must be 64-hex")
    if qualification_receipt_sha256 is not None:
        require(HEX64.fullmatch(qualification_receipt_sha256) is not None,
                "qualification receipt sha256 must be 64-hex")
    return version, head, frozen_parent


def verify_ci_results(needs_json: str) -> int:
    try:
        needs = json.loads(needs_json)
    except (ValueError, TypeError) as exc:
        raise ReleaseError(f"invalid CI needs JSON: {exc}") from exc
    require(isinstance(needs, dict) and bool(needs), "CI needs must be a nonempty mapping")
    for name, job in needs.items():
        require(isinstance(name, str) and bool(name) and isinstance(job, dict) and
                job.get("result") == "success", f"CI job {name!r} did not succeed")
    return len(needs)

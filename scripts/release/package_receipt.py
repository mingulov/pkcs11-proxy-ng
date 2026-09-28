"""Quality-receipt writer for the release orchestrator.

Behind the ``write-receipt`` subcommand of ``scripts/release_checks.py``.
Writes the machine-readable receipt that ``scripts/verify-quality-receipt.sh``
parses (``subject_sha`` plus the eight gates with exact ``pass`` verdicts);
every refusal raises :class:`ReleaseError`.
"""

from __future__ import annotations

import re
from pathlib import Path

from .package_model import ReleaseError, require


VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
GATES = ("fmt", "check", "test", "clippy", "msrv", "audit", "deny",
         "release_dry_run")


def write_receipt(output: Path, version: str, subject_sha: str,
                  run_url: str | None = None) -> Path:
    """Write a quality receipt; refuse unless every input is exact."""
    require(isinstance(version, str) and VERSION.match(version) is not None,
            f"version {version!r} is not MAJOR.MINOR.PATCH")
    require(isinstance(subject_sha, str) and
            SHA40.match(subject_sha) is not None,
            f"subject SHA {subject_sha!r} is not a 40-hex SHA")
    target = Path(output)
    require(not target.exists(),
            f"refusing to overwrite existing receipt {target}")
    lines = [f"# Quality receipt v{version}", "",
             f"subject_sha: {subject_sha}", ""]
    lines.extend(f"{gate}: pass" for gate in GATES)
    lines += ["", f"generated_by: cut-release {run_url or 'manual'}", ""]
    try:
        target.write_text("\n".join(lines), encoding="utf-8")
    except OSError as exc:
        raise ReleaseError(f"cannot write receipt {target}: {exc}") from exc
    return target

#!/usr/bin/env python3
"""Run every public script regression; absent prerequisites/skips fail closed."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
# Direct test dependencies, including the restricted perf-harness tool farm.
# Providers, Docker, gh and network services are replaced by controlled fixtures.
TOOLS = (
    "bash", "git", "jq", "openssl", "timeout", "tar", "gzip", "cargo",
    "sh", "dirname", "mktemp", "mkdir", "rm", "mv", "cat", "touch",
    "awk", "seq", "sort", "chmod", "cksum",
)


def preflight() -> None:
    requirements = (ROOT / "requirements-script-tests.txt").read_text().splitlines()
    expected = next(line.removeprefix("PyYAML==") for line in requirements
                    if line.startswith("PyYAML=="))
    try:
        import yaml
    except ImportError as error:
        raise RuntimeError("PyYAML is required; install requirements-script-tests.txt") from error
    if yaml.__version__ != expected:
        raise RuntimeError(f"PyYAML {expected} is required; found {yaml.__version__}")
    missing = [tool for tool in TOOLS if shutil.which(tool) is None]
    if missing:
        raise RuntimeError(f"missing required tools: {', '.join(missing)}")
    # Check the options the shell harnesses use instead of rejecting compatible
    # coreutils implementations solely because their version banner differs.
    subprocess.run(["timeout", "--signal=TERM", "--kill-after=1s", "1s",
                    sys.executable, "-c", "pass"], text=True, capture_output=True,
                   timeout=10, check=True)


def main() -> int:
    try:
        preflight()
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests/scripts"),
                                                  pattern="test_*.py")
        count = suite.countTestCases()
        if count == 0:
            raise RuntimeError("zero tests collected from tests/scripts")
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"script regression preflight failed: {error}", file=sys.stderr)
        return 2
    print(f"Collected {count} script regression tests", file=sys.stderr)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.skipped:
        print(f"script regression gate refused {len(result.skipped)} unexpected skip(s)",
              file=sys.stderr)
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())

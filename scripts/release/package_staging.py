"""Create an isolated staging-only Cargo publish probe."""

from pathlib import Path
import re
import shutil
import tomllib

from .package_model import require


POSITIVE_NUMBER = re.compile(r"[1-9][0-9]*\Z")
PROBE_NAME = "pkcs11-proxy-ng-publish-probe"


def staging_probe(repo: Path, destination: Path, run_id: str, attempt: str,
                  registry: str = "staging") -> str:
    require(registry == "staging", "probe must use the staging registry")
    require(POSITIVE_NUMBER.fullmatch(run_id) is not None and
            POSITIVE_NUMBER.fullmatch(attempt) is not None,
            "run ID and attempt must be positive decimal integers")
    version = f"0.0.0-ci.{run_id}.{attempt}"
    template = repo / "tools/publish-probe"
    manifest = tomllib.loads((template / "Cargo.toml").read_text(encoding="utf-8"))
    package = manifest.get("package", {})
    require(package.get("name") == PROBE_NAME and package.get("publish") == ["staging"] and
            "workspace" in manifest and not manifest["workspace"] and
            "dependencies" not in manifest, "probe template violates staging isolation")
    require(not destination.exists(), "probe destination already exists")
    source = (template / "Cargo.toml").read_text(encoding="utf-8")
    require('version = "0.0.0-ci.0.0"' in source, "probe template version marker is missing")
    # copytree creates the destination exclusively; no existing files are overwritten.
    shutil.copytree(template, destination)
    (destination / "Cargo.toml").write_text(
        source.replace('version = "0.0.0-ci.0.0"', f'version = "{version}"', 1),
        encoding="utf-8")
    return version

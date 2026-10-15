"""Stage checksum-bound Linux and Windows binary bundles."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import tarfile
import time
import zipfile

from .package_binaries import TARGETS, require_registry_provenance
from .package_model import ReleaseError, require
from .package_notices import safe_upstream_relative

#: Immutable online home for bundle links whose targets are not shipped
#: in the archive. Rewritten links pin the exact staged ``v{version}``
#: tag — never a mutable branch.
ONLINE_REPO_BASE = "https://github.com/mingulov/pkcs11-proxy-ng"

_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")

EXPECTED_ARTIFACTS = {
    TARGETS[0]: {"pkcs11-proxy-ng": ("pkcs11-proxy-ng", "bin"),
                 "pkcs11-proxy-ng-cli": ("pkcs11-proxy-ng-cli", "bin"),
                 "libpkcs11_proxy_ng_shim.so": ("pkcs11-proxy-ng-shim", "lib")},
    TARGETS[1]: {"pkcs11-proxy-ng.exe": ("pkcs11-proxy-ng", "bin"),
                 "pkcs11-proxy-ng-cli.exe": ("pkcs11-proxy-ng-cli", "bin"),
                 "pkcs11_proxy_ng_shim.dll": ("pkcs11-proxy-ng-shim", "lib"),
                 "cross_width_smoke.exe": ("pkcs11-proxy-ng-shim", "example")},
    TARGETS[2]: {"pkcs11-proxy-ng": ("pkcs11-proxy-ng", "bin"),
                 "pkcs11-proxy-ng-cli": ("pkcs11-proxy-ng-cli", "bin"),
                 "libpkcs11_proxy_ng_shim.dylib": ("pkcs11-proxy-ng-shim", "lib")},
}


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise ReleaseError(f"cannot read {path}: {exc}") from exc
    require(isinstance(value, dict), f"invalid object in {path}")
    return value


def validate_prepared_bundle(binaries_dir: Path, provenance_path: Path,
                             notices_dir: Path, *, inventory_path: Path | None = None,
                             package_dir: Path | None = None) -> tuple[dict, dict]:
    """Check final bytes against the build and notice inventories before staging."""
    binaries_dir, provenance_path, notices_dir = map(Path, (binaries_dir, provenance_path, notices_dir))
    provenance = _json(provenance_path)
    notices = _json(notices_dir / "notice-inventory.json")
    require(provenance.get("format_version") == notices.get("format_version") == 1 and
            provenance.get("target") in TARGETS and
            provenance.get("target") == notices.get("target") and
            provenance.get("source_mode") == notices.get("source_mode") and
            provenance.get("source_commit") == notices.get("source_commit") and
            notices.get("build_provenance_sha256") == _hash(provenance_path),
            "notices do not match binary build provenance")
    tools = provenance.get("tools")
    rust_std = notices.get("rust_std")
    require(isinstance(tools, dict) and
            str(tools.get("rustc", "")).startswith("rustc 1.98.1 ") and
            str(tools.get("cargo", "")).startswith("cargo 1.98.1 ") and
            isinstance(rust_std, dict) and rust_std.get("version") == tools["rustc"],
            "notice toolchain attribution differs from binary build")
    source = provenance["source_mode"]
    require(source in ("archive", "registry", "workspace"), "unsupported binary source mode")
    if source == "registry":
        require(inventory_path is not None and package_dir is not None,
                "registry staging requires inventory and verified archives")
        require_registry_provenance(provenance_path, inventory_path, package_dir, binaries_dir)
    else:
        require(provenance.get("github_publication_eligible") is False,
                "non-registry staging cannot claim publication eligibility")
    artifacts = provenance.get("artifacts")
    require(isinstance(artifacts, list) and artifacts and
            artifacts == notices.get("artifacts") and
            all(isinstance(item, dict) and isinstance(item.get("name"), str)
                for item in artifacts), "notice artifact inventory differs")
    expected = {item["name"] for item in artifacts}
    expected_records = EXPECTED_ARTIFACTS[provenance["target"]]
    require(expected == set(expected_records) and
            all((item.get("package"), item.get("kind")) == expected_records[item["name"]]
                for item in artifacts), "binary artifact contract differs")
    require(len(expected) == len(artifacts) and binaries_dir.is_dir() and
            {item.name for item in binaries_dir.iterdir()} == expected,
            "prepared binary set differs from provenance")
    for record in artifacts:
        name = record["name"]
        path = binaries_dir / name
        require(safe_upstream_relative(name) and "/" not in name and path.is_file() and not path.is_symlink() and
                isinstance(record.get("size"), int) and not isinstance(record["size"], bool) and
                path.stat().st_size == record["size"] > 0 and _hash(path) == record.get("sha256"),
                f"prepared binary differs from provenance: {name}")
    files = notices.get("files")
    require(isinstance(files, dict) and "THIRD_PARTY_NOTICES" in files and
            "license-material/rust-std/COPYRIGHT-library.html" in files and
            all(isinstance(name, str) and safe_upstream_relative(name) and
                isinstance(value, str) and len(value) == 64 for name, value in files.items()),
            "notice file inventory is incomplete or unsafe")
    require(rust_std.get("material") == "license-material/rust-std/COPYRIGHT-library.html" and
            rust_std.get("sha256") == files[rust_std["material"]] and
            (source == "workspace" or
             notices.get("source_inventory_sha256") == provenance.get("inventory_sha256")),
            "notice source or Rust attribution hash differs")
    observed = {item.relative_to(notices_dir).as_posix() for item in notices_dir.rglob("*")
                if item.is_file()}
    require(observed == set(files) | {"notice-inventory.json"},
            "notice directory has missing or unrecorded files")
    for name, expected_hash in files.items():
        path = notices_dir / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size and
                _hash(path) == expected_hash, f"notice material differs: {name}")
    return provenance, notices


def online_blob_url(version: str, repo_relative: str, *, is_dir: bool = False) -> str:
    """Immutable online reference for a repository path at a staged version."""
    kind = "tree" if is_dir else "blob"
    return f"{ONLINE_REPO_BASE}/{kind}/v{version}/{repo_relative}"


def bundle_doc_mapping(repo: Path, version: str, target: str | None = None) -> dict[str, Path]:
    """Repository docs and config templates shipped in the bundle.

    Unix bundles carry the install guide, the runbook/error/support
    material the guide needs, and complete secure config templates,
    all at repository-relative paths. The Windows bundle carries only
    the top-level README/CHANGELOG (its template ships separately);
    every target's markdown links are repaired by
    :func:`repair_bundle_markdown_links`.
    """
    repo = Path(repo)
    mapping = {"README.md": repo / "README.md", "CHANGELOG.md": repo / "CHANGELOG.md"}
    if target == TARGETS[1]:
        return mapping
    install = repo / "doc/release/bundle-install.md"
    require(install.is_file() and not install.is_symlink() and install.stat().st_size > 0,
            "bundle install guide is missing: expected doc/release/bundle-install.md")
    mapping["INSTALL.md"] = install
    notes_name = f"v{version}-release-notes.md"
    notes_path = repo / "doc/release" / notes_name
    require(notes_path.is_file() and not notes_path.is_symlink() and
            notes_path.stat().st_size > 0,
            f"release notes for version {version} are missing: "
            f"expected doc/release/{notes_name}")
    for name in ("beta-support-matrix.md", "mtls-setup.md", "parity-validation.md",
                 notes_name):
        mapping[f"doc/release/{name}"] = repo / "doc/release" / name
    if target == TARGETS[2]:
        mac_doc = repo / "doc/release/macos-install.md"
        require(mac_doc.is_file() and not mac_doc.is_symlink() and
                mac_doc.stat().st_size > 0,
                "macos-install.md is missing: expected doc/release/macos-install.md")
        mapping["doc/release/macos-install.md"] = mac_doc
    for name in ("doc/runbooks/operating-pkcs11-proxy-ng.md", "doc/error-reference.md",
                 "examples/configs/prod/proxy.toml", "examples/configs/staging/proxy.toml",
                 "examples/configs/bundle/proxy.toml"):
        mapping[name] = repo / name
    return mapping


def repair_bundle_markdown_links(stage_root: Path, mapping: dict[str, Path],
                                 repo: Path, version: str) -> dict[str, list[str]]:
    """Repair staged markdown links; report ``{staged file: [online URLs]}``.

    Links that already resolve inside the staged tree are kept. A link
    that misses the staged tree is resolved against its source file in
    the repository: when the repository target ships in the bundle
    under another staged path (e.g. the top-level install guide
    pointing at repository-relative material), the link is rewritten
    to the bundle-local path; otherwise it is rewritten to an
    immutable version-pinned online reference. Links broken in the
    repository itself are left untouched so link checks flag them.
    """
    stage_root, repo = Path(stage_root), Path(repo)
    stage_anchor = stage_root.resolve()
    repo_anchor = repo.resolve()
    by_source = {Path(source).resolve(): staged for staged, source in mapping.items()}
    report: dict[str, list[str]] = {}
    for staged_rel in sorted(mapping):
        if not staged_rel.endswith(".md"):
            continue
        staged_file = stage_root / staged_rel
        source_file = Path(mapping[staged_rel])
        text = staged_file.read_text(encoding="utf-8")
        rewritten: list[str] = []

        def fix(match: re.Match[str]) -> str:
            target = match.group(1)
            if "://" in target or target.startswith(("mailto:", "#")):
                return match.group(0)
            bare, sep, frag = target.partition("#")
            bare = bare.strip().strip("<>")
            if not bare:
                return match.group(0)
            staged_hit = (staged_file.parent / bare).resolve()
            if staged_hit.is_relative_to(stage_anchor) and staged_hit.exists():
                return match.group(0)
            repo_hit = (source_file.parent / bare).resolve()
            try:
                repo_rel = repo_hit.relative_to(repo_anchor).as_posix()
            except ValueError:
                return match.group(0)
            if not repo_hit.exists():
                return match.group(0)
            suffix = f"{sep}{frag}" if sep else ""
            if repo_hit in by_source:
                local = os.path.relpath(stage_anchor / by_source[repo_hit],
                                        staged_file.parent).replace(os.sep, "/")
                replacement = local + suffix
            else:
                replacement = online_blob_url(version, repo_rel,
                                              is_dir=repo_hit.is_dir()) + suffix
                rewritten.append(replacement)
            start, end = match.span(1)
            base = match.start(0)
            whole = match.group(0)
            return whole[:start - base] + replacement + whole[end - base:]

        staged_file.write_text(_LINK_RE.sub(fix, text), encoding="utf-8")
        if rewritten:
            report[staged_rel] = rewritten
    return report


def _bundle_files(repo: Path, binaries_dir: Path, provenance_path: Path,
                  notices_dir: Path, target: str, version: str) -> dict[str, Path]:
    own = notices_dir / f"license-material/pkcs11-proxy-ng-{version}/licenses"
    files = {"LICENSE-APACHE": own / "LICENSE-APACHE", "LICENSE-MIT": own / "LICENSE-MIT",
             "build-provenance.json": provenance_path}
    files.update(bundle_doc_mapping(repo, version, target))
    for item in notices_dir.rglob("*"):
        if item.is_file():
            files[item.relative_to(notices_dir).as_posix()] = item
    if target in (TARGETS[0], TARGETS[2]):
        shim_name = ("libpkcs11_proxy_ng_shim.dylib" if target == TARGETS[2]
                     else "libpkcs11_proxy_ng_shim.so")
        files.update({"bin/pkcs11-proxy-ng": binaries_dir / "pkcs11-proxy-ng",
                      "bin/pkcs11-proxy-ng-cli": binaries_dir / "pkcs11-proxy-ng-cli",
                      f"lib/pkcs11/{shim_name}": binaries_dir / shim_name})
    else:
        files.update({"bin/pkcs11-proxy-ng.exe": binaries_dir / "pkcs11-proxy-ng.exe",
                      "bin/pkcs11-proxy-ng-cli.exe": binaries_dir / "pkcs11-proxy-ng-cli.exe",
                      "bin/cross_width_smoke.exe": binaries_dir / "cross_width_smoke.exe",
                      "lib/pkcs11_proxy_ng_shim.dll": binaries_dir / "pkcs11_proxy_ng_shim.dll",
                      "proxy.toml.template": repo / "packaging/windows/proxy.toml.template",
                      "Run-Pkcs11ProxyNg.ps1": repo / "packaging/windows/Run-Pkcs11ProxyNg.ps1"})
    return files


def stage_bundle(repo: Path, binaries_dir: Path, provenance_path: Path,
                 notices_dir: Path, output: Path, *, timestamp: int,
                 inventory_path: Path | None = None, package_dir: Path | None = None) -> Path:
    """Build a deterministic archive from prepared artifacts and matching notices."""
    repo, binaries_dir, provenance_path, notices_dir, output = map(
        Path, (repo, binaries_dir, provenance_path, notices_dir, output))
    provenance, _ = validate_prepared_bundle(
        binaries_dir, provenance_path, notices_dir,
        inventory_path=inventory_path, package_dir=package_dir)
    require(isinstance(timestamp, int) and timestamp >= 315532800, "bundle timestamp must be 1980 or later")
    require(not output.is_symlink() and (not output.exists() or output.is_dir()),
            "bundle output must be a directory")
    target = provenance["target"]
    version = provenance.get("version")
    require(isinstance(version, str) and version, "binary provenance version is absent")
    name = f"pkcs11-proxy-ng-v{version}-{target}"
    mapping = _bundle_files(repo, binaries_dir, provenance_path, notices_dir, target, version)
    for relative, source in mapping.items():
        require(safe_upstream_relative(relative) and source.is_file() and not source.is_symlink() and
                source.stat().st_size > 0, f"missing or unsafe bundle input: {relative}")
    output.mkdir(parents=True, exist_ok=True)
    stage = output / name
    archive_suffix = ".zip" if target == TARGETS[1] else ".tar.gz"
    require(not stage.exists() and not (output / f"{name}{archive_suffix}").exists(),
            "bundle already exists in output directory")
    for relative, source in sorted(mapping.items()):
        dest = stage / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
        require(_hash(dest) == _hash(source), f"staged file changed: {relative}")
    # Deterministic link repair on the staged markdown only: bundled
    # local links resolve in-archive, the rest become immutable
    # version-pinned online references. The final integrity check
    # below compares archived bytes against these staged bytes.
    repair_bundle_markdown_links(stage, mapping, repo, version)
    if target in (TARGETS[0], TARGETS[2]):
        archive = output / f"{name}.tar.gz"
        with archive.open("wb") as stream, gzip.GzipFile(fileobj=stream, mode="wb", filename="", mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as bundle:
                for relative in sorted(mapping):
                    source = stage / relative
                    info = tarfile.TarInfo(f"{name}/{relative}")
                    info.size = source.stat().st_size
                    info.mode = 0o755 if relative.startswith(("bin/", "lib/")) else 0o644
                    info.uid = info.gid = 0
                    info.mtime = timestamp
                    with source.open("rb") as reader:
                        bundle.addfile(info, reader)
        with tarfile.open(archive, "r:gz") as bundle:
            contained = {member.name: bundle.extractfile(member).read() for member in bundle}
    else:
        archive = output / f"{name}.zip"
        date = time.gmtime(timestamp)
        stamp = (date.tm_year, date.tm_mon, date.tm_mday, date.tm_hour, date.tm_min, date.tm_sec)
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
            for relative in sorted(mapping):
                info = zipfile.ZipInfo(f"{name}/{relative}", stamp)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (0o755 if relative.startswith(("bin/", "lib/")) else 0o644) << 16
                bundle.writestr(info, (stage / relative).read_bytes())
        with zipfile.ZipFile(archive) as bundle:
            require(bundle.testzip() is None, "ZIP integrity check failed")
            contained = {item.filename: bundle.read(item) for item in bundle.infolist()}
    require(set(contained) == {f"{name}/{relative}" for relative in mapping} and
            all(digest == hashlib.sha256(contained[f"{name}/{relative}"]).hexdigest()
                for relative, digest in {key: _hash(stage / key)
                                          for key in mapping}.items()),
            "final bundle file set or hashes differ")
    return archive

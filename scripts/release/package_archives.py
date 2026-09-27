"""Bounded inspection and safe extraction of Cargo source archives."""

from __future__ import annotations

from fnmatch import fnmatchcase
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tomllib

from release.package_model import (INTERNAL, PACKAGES, ReleaseError, checked_workspace,
                                   effective_dep, git, read_toml, require, source_sections)

MAX_FILE = 16 * 1024 * 1024
MAX_CONTENT = 64 * 1024 * 1024
MAX_TAR = 72 * 1024 * 1024
MAX_FILES = 1000
MAX_MEMBERS = 1000
MAX_METADATA = 2 * 1024 * 1024
GENERATED = {"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", ".cargo_vcs_info.json"}
PACKAGE_FIELDS = ("name", "version", "edition", "rust-version", "license", "repository",
                  "publish", "description", "readme", "categories", "keywords", "include",
                  "documentation", "homepage", "license-file", "exclude")


def parsed_bytes(data: bytes, label: str) -> dict:
    try:
        return tomllib.loads(data.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseError(f"invalid {label}: {exc}") from exc


def safe_relative(path: str) -> bool:
    return (bool(path) and not path.startswith("/") and "\\" not in path and
            all(part not in ("", ".", "..") and not part.startswith(".")
                for part in path.split("/")))


def archive_entries(archive: Path, name: str, version: str) -> dict[str, bytes]:
    prefix = f"{name}-{version}"
    try:
        require(archive.is_file() and not archive.is_symlink(), f"missing or linked archive {archive}")
        require(archive.stat().st_size <= MAX_TAR, f"compressed archive too large: {archive}")
        with gzip.open(archive, "rb") as compressed:
            raw = compressed.read(MAX_TAR + 1)
        require(len(raw) <= MAX_TAR, f"expanded tar too large: {archive}")
        entries: dict[str, bytes] = {}
        seen: set[str] = set()
        total = 0
        padded_contents = 0
        members = 0
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as package:
            for member in package:
                members += 1
                require(members <= MAX_MEMBERS, f"too many archive headers: {archive}")
                require(sum(len(str(key)) + len(str(value)) for key, value in member.pax_headers.items()) <= 16 * 1024,
                        f"archive header metadata too large: {member.name}")
                path = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
                require(path == prefix or path.startswith(prefix + "/"),
                        f"archive entry outside {prefix}: {path}")
                relative = "" if path == prefix else path[len(prefix) + 1:]
                require(path == prefix or safe_relative(relative) or relative == ".cargo_vcs_info.json",
                        f"unsafe archive path: {path}")
                require(member.linkname == "", f"archive member has link metadata: {path}")
                require(path not in seen, f"duplicate archive member: {path}")
                seen.add(path)
                if member.isdir():
                    require(member.size == 0, f"directory has payload: {path}")
                    continue
                require(member.isfile() and relative, f"archive link or special member: {path}")
                require(len(entries) < MAX_FILES, f"too many archive files: {archive}")
                require(member.size <= MAX_FILE, f"archive file too large: {path}")
                total += member.size
                padded_contents += ((member.size + 511) // 512) * 512
                require(total <= MAX_CONTENT, f"archive content too large: {archive}")
                stream = package.extractfile(member)
                require(stream is not None, f"archive file unreadable: {path}")
                data = stream.read(MAX_FILE + 1)
                require(len(data) == member.size, f"archive file length mismatch: {path}")
                entries[relative] = data
        require(len(raw) - padded_contents <= MAX_METADATA,
                f"archive headers and directory metadata too large: {archive}")
        return entries
    except (OSError, EOFError, gzip.BadGzipFile, tarfile.TarError) as exc:
        raise ReleaseError(f"cannot inspect {archive}: {exc}") from exc


def package_sources(repo: Path, directory: str, source: dict, tracked: set[str]) -> dict[str, bytes]:
    root = repo / "crates" / directory
    patterns = source["package"]["include"]
    require(isinstance(patterns, list), f"invalid include list for {directory}")
    expected = {}
    for path in root.rglob("*"):
        require(not path.is_symlink(), f"package source symlink forbidden: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        include = any(fnmatchcase(relative, pattern) for pattern in patterns)
        # Cargo includes this one server test README as a target asset even
        # though the narrow package include list omits repository tests.
        if directory == "server" and relative == "tests/README.md":
            include = True
        if include:
            require(safe_relative(relative), f"unsafe package source path: {relative}")
            require(f"crates/{directory}/{relative}" in tracked,
                    f"{directory} package source is absent from HEAD: {relative}")
            expected[relative] = path.read_bytes()
    require("Cargo.toml" in expected and "README.md" in expected, f"missing package source in {root}")
    for license_name in ("LICENSE-APACHE", "LICENSE-MIT"):
        require(expected.get(license_name) == (repo / license_name).read_bytes(),
                f"{directory} license differs from root")
    return expected


def inherited(source: dict, workspace: dict, key: str):
    value = source.get("package", {}).get(key)
    if value == {"workspace": True}:
        return workspace.get("workspace", {}).get("package", {}).get(key)
    return value


def normalized_dep(spec: object, workspace: dict, name: str) -> dict:
    effective = effective_dep(spec, workspace, name)
    expected = {"version": effective.get("version"),
                "features": sorted(set(effective.get("features", []))),
                "optional": effective.get("optional", False),
                "default-features": effective.get("default-features", True)}
    for key in ("package", "registry", "registry-index"):
        if key in effective:
            expected[key] = effective[key]
    return expected


def validate_dependencies(source: dict, workspace: dict, normalized: dict, name: str) -> None:
    source_groups = dict(source_sections(source))
    normalized_groups = dict(source_sections(normalized))
    require(not {label for label, deps in normalized_groups.items() if deps and label not in source_groups},
            f"{name} has unexpected normalized dependency sections")
    for label, source_deps in source_groups.items():
        actual_deps = normalized_groups.get(label, {})
        omitted = {dep for dep, spec in source_deps.items()
                   if label.endswith("dev-dependencies") and dep in INTERNAL and
                   "version" not in effective_dep(spec, workspace, dep)}
        require(set(actual_deps) == set(source_deps) - omitted,
                f"{name} normalized {label} dependency names differ from source")
        for dep, source_spec in source_deps.items():
            if dep in omitted:
                continue
            actual = actual_deps[dep]
            require(isinstance(actual, dict), f"{name} {dep} normalized dependency is invalid")
            require("path" not in actual and "git" not in actual and "branch" not in actual and
                    "rev" not in actual and "tag" not in actual,
                    f"{name} archive contains a non-registry dependency {dep}")
            expected = normalized_dep(source_spec, workspace, dep)
            for key, value in expected.items():
                found = sorted(set(actual.get(key, []))) if key == "features" else actual.get(
                    key, False if key == "optional" else True if key == "default-features" else None)
                require(found == value, f"{name} {dep} {key} differs from source")
            require(set(actual) <= {"version", "features", "optional", "default-features",
                                    "package", "registry", "registry-index"},
                    f"{name} {dep} has unexpected dependency fields")


def expected_targets(root: Path, source: dict, entries: dict[str, bytes]) -> dict[str, list[dict]]:
    result = {}
    package = source["package"]
    stem = package["name"].replace("-", "_")
    if (root / "src/lib.rs").is_file():
        result["lib"] = [{"name": stem, "path": "src/lib.rs"}]
    if (root / "src/main.rs").is_file():
        result["bin"] = [{"name": package["name"], "path": "src/main.rs"}]
    for kind in ("lib", "bin", "example", "test", "bench"):
        if kind in ("lib", "bin") and kind in source:
            configured = source[kind]
            result[kind] = [configured] if isinstance(configured, dict) else configured
        elif kind not in ("lib", "bin") and kind in source:
            result[kind] = source[kind]
    for kind, folder in (("example", "examples"), ("test", "tests"), ("bench", "benches")):
        paths = sorted((root / folder).glob("*.rs")) if (root / folder).is_dir() else []
        if paths and kind not in result:
            result[kind] = [{"name": path.stem, "path": f"{folder}/{path.name}"} for path in paths]
    return {kind: [target for target in targets
                   if target.get("path", {"lib": "src/lib.rs", "bin": "src/main.rs"}.get(kind)) in entries]
            for kind, targets in result.items()
            if any(target.get("path", {"lib": "src/lib.rs", "bin": "src/main.rs"}.get(kind)) in entries
                   for target in targets)}


def validate_manifest(repo: Path, directory: str, name: str, version: str,
                      entries: dict[str, bytes], workspace: dict) -> None:
    root = repo / "crates" / directory
    source = read_toml(root / "Cargo.toml")
    require(entries.get("Cargo.toml.orig") == (root / "Cargo.toml").read_bytes(),
            f"{name} original manifest differs from source")
    require("Cargo.toml" in entries, f"{name} missing normalized manifest")
    normalized = parsed_bytes(entries["Cargo.toml"], f"{name} Cargo.toml")
    require(set(normalized) <= {"package", "features", "lib", "bin", "example", "test",
                                "bench", "dependencies", "dev-dependencies", "build-dependencies",
                                "target", "lints", "badges"},
            f"{name} normalized manifest has unexpected sections")
    actual = normalized.get("package", {})
    require(actual.get("name") == name and actual.get("version") == version,
            f"{name} normalized identity differs")
    for key in PACKAGE_FIELDS:
        expected = inherited(source, workspace, key)
        if expected is not None:
            require(actual.get(key) == expected, f"{name} normalized {key} differs from source")
    for key in ("readme", "license-file"):
        value = actual.get(key)
        if value is not None:
            require(isinstance(value, str) and safe_relative(value) and value in entries,
                    f"{name} normalized {key} references missing or sibling source")
    require(set(actual) <= set(PACKAGE_FIELDS) | {"build", "resolver", "metadata", "autolib",
                                                    "autobins", "autoexamples", "autotests", "autobenches"},
            f"{name} normalized package has unexpected fields")
    for pattern in actual.get("include", []):
        require(isinstance(pattern, str) and pattern and not pattern.startswith("/") and
                "\\" not in pattern and all(part not in ("", ".", "..") for part in pattern.split("/")),
                f"{name} manifest includes unsafe path")
    source_build = inherited(source, workspace, "build")
    expected_build = source_build if source_build is not None else (
        "build.rs" if (root / "build.rs").is_file() else False)
    require(actual.get("build") == expected_build, f"{name} normalized build field differs")
    if isinstance(expected_build, str):
        require(safe_relative(expected_build) and expected_build in entries,
                f"{name} build script references missing or sibling source")
    require(actual.get("resolver") == workspace.get("workspace", {}).get("resolver"),
            f"{name} normalized resolver differs")
    for key in ("autolib", "autobins", "autoexamples", "autotests", "autobenches"):
        require(actual.get(key) == source.get("package", {}).get(key, False),
                f"{name} normalized {key} differs")
    require(normalized.get("features", {}) == source.get("features", {}),
            f"{name} normalized features differ")
    require(normalized.get("package", {}).get("metadata", {}) == source.get("package", {}).get("metadata", {}),
            f"{name} normalized metadata differs")
    targets_by_kind = expected_targets(root, source, entries)
    for kind, targets in targets_by_kind.items():
        actual_targets = normalized.get(kind, [])
        if isinstance(actual_targets, dict):
            actual_targets = [actual_targets]
        require(len(actual_targets) == len(targets), f"{name} normalized {kind} targets differ")
        for expected, found in zip(targets, actual_targets):
            for key, value in expected.items():
                require(found.get(key) == value, f"{name} normalized {kind} {key} differs")
            require("path" in found and safe_relative(found["path"]) and found["path"] in entries,
                    f"{name} normalized {kind} target path invalid")
    for kind in ("lib", "bin", "example", "test", "bench"):
        require(kind in targets_by_kind or kind not in normalized,
                f"{name} has unexpected {kind} target")
    source_lints = source.get("lints", {})
    if source_lints == {"workspace": True}:
        source_lints = workspace.get("workspace", {}).get("lints", {})
    require(normalized.get("lints", {}) == source_lints, f"{name} normalized lints differ")
    validate_dependencies(source, workspace, normalized, name)
    require("patch" not in normalized and "replace" not in normalized and
            "workspace" not in normalized, f"{name} normalized manifest references other sources")


def validate_archive(repo: Path, package_dir: Path, name: str, directory: str,
                     version: str, commit: str, workspace: dict,
                     tracked: set[str]) -> tuple[dict, dict[str, bytes]]:
    archive = package_dir / f"{name}-{version}.crate"
    entries = archive_entries(archive, name, version)
    source = read_toml(repo / "crates" / directory / "Cargo.toml")
    expected = package_sources(repo, directory, source, tracked)
    expected.pop("Cargo.toml")
    require(set(entries) - GENERATED == set(expected), f"{name} archive source file set differs")
    for path, content in expected.items():
        require(entries[path] == content, f"{name} archive differs from source: {path}")
    require(".cargo_vcs_info.json" in entries, f"{name} lacks VCS provenance")
    try:
        vcs = json.loads(entries[".cargo_vcs_info.json"])
    except (ValueError, UnicodeError) as exc:
        raise ReleaseError(f"{name} invalid VCS provenance: {exc}") from exc
    require(vcs.get("git", {}).get("sha1") == commit and
            vcs.get("path_in_vcs") == f"crates/{directory}" and
            vcs.get("dirty", False) is False and
            set(vcs) <= {"git", "path_in_vcs", "dirty"},
            f"{name} VCS provenance differs from clean source")
    require(set(vcs["git"]) == {"sha1"}, f"{name} VCS provenance has unexpected fields")
    validate_manifest(repo, directory, name, version, entries, workspace)
    require("Cargo.lock" in entries, f"{name} lacks generated Cargo.lock")
    lock = parsed_bytes(entries["Cargo.lock"], f"{name} Cargo.lock")
    require(isinstance(lock.get("package"), list), f"{name} invalid generated Cargo.lock")
    for package in lock["package"]:
        require(isinstance(package, dict), f"{name} invalid generated lock package")
        source = package.get("source")
        require(source is None or
                (isinstance(source, str) and source.startswith("registry+https://")),
                f"{name} generated lock contains a non-registry source")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    return ({"name": name, "version": version, "archive": archive.name,
             "sha256": digest, "files": sorted(entries)}, entries)


def _inspect(repo: Path, package_dir: Path) -> tuple[dict, dict[str, dict[str, bytes]]]:
    version = checked_workspace(repo)
    commit = git(repo, "rev-parse", "HEAD")
    require(not git(repo, "status", "--porcelain", "--untracked-files=all"),
            "source checkout has tracked or untracked changes")
    require(git(repo, "ls-tree", "-r", "--name-only", "HEAD", "--", "Cargo.lock") == "Cargo.lock",
            "workspace Cargo.lock is absent from HEAD")
    require(package_dir.is_dir(), f"missing package directory: {package_dir}")
    wanted = {f"{name}-{version}.crate" for name, _ in PACKAGES}
    actual = {path.name for path in package_dir.glob("*.crate")}
    require(actual == wanted, f"package archive set differs: missing {sorted(wanted - actual)}, extra {sorted(actual - wanted)}")
    workspace = read_toml(repo / "Cargo.toml")
    tracked = set(git(repo, "ls-tree", "-r", "--name-only", "HEAD", "--", "crates").splitlines())
    records = []
    contents = {}
    for name, directory in PACKAGES:
        record, entries = validate_archive(repo, package_dir, name, directory, version, commit, workspace, tracked)
        records.append(record)
        contents[name] = entries
    root_lock = read_toml(repo / "Cargo.lock")
    baseline = {(package["name"], package["version"], package.get("source"),
                 package.get("checksum")) for package in root_lock.get("package", [])
                if package.get("source") is not None}
    hashes = {record["name"]: record["sha256"] for record in records}
    for name, entries in contents.items():
        lock = parsed_bytes(entries["Cargo.lock"], f"{name} Cargo.lock")
        seen = set()
        for package in lock["package"]:
            identity = (package.get("name"), package.get("version"), package.get("source"))
            require(identity not in seen, f"{name} generated lock repeats package identity")
            seen.add(identity)
            locked_name, locked_version, source = identity
            if locked_name in INTERNAL:
                require(locked_version == version, f"{name} locks a wrong internal package version")
                if source is not None:
                    require(package.get("checksum") == hashes[locked_name],
                            f"{name} internal archive checksum differs")
            else:
                require(source is not None and
                        (locked_name, locked_version, source, package.get("checksum")) in baseline,
                        f"{name} external lock identity differs from committed workspace lock")
    require(not git(repo, "status", "--porcelain", "--untracked-files=all"),
            "source checkout changed during inspection")
    return ({"format_version": 1, "source_commit": commit, "version": version,
             "packages": records}, contents)


def inspect_archives(repo: Path, package_dir: Path, *, write: bool = False) -> dict:
    inventory, _ = _inspect(Path(repo), Path(package_dir))
    if write:
        package_dir = Path(package_dir)
        (package_dir / "inventory.json").write_text(
            json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (package_dir / "SHA256SUMS").write_text(
            "".join(f"{record['sha256']}  {record['archive']}\n" for record in inventory["packages"]),
            encoding="utf-8")
    return inventory


def extract_verified_archives(repo: Path, package_dir: Path, destination: Path) -> dict[str, Path]:
    inventory, archives = _inspect(Path(repo), Path(package_dir))
    destination = Path(destination)
    require(all(not path.is_symlink() for path in (destination, *destination.parents)),
            f"extraction path follows a symlink: {destination}")
    require(not destination.exists() and not destination.is_symlink(),
            f"extraction destination already exists: {destination}")
    destination.mkdir(parents=True, exist_ok=False)
    roots = {}
    for record in inventory["packages"]:
        name = record["name"]
        root = destination / f"{name}-{inventory['version']}"
        root.mkdir()
        for relative, data in archives[name].items():
            target = root.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(data)
        roots[name] = root
    return roots

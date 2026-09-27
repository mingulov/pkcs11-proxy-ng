"""Collect exact upstream notice material from checksum-bound build inputs."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tomllib

from .package_archives import archive_entries
from .package_binaries import ROOTS, TARGETS, require_registry_provenance, validate_build_graph
from .package_model import INTERNAL, PACKAGES, ReleaseError, require
from .package_registry import read_inventory


LICENSE_NAME = re.compile(r"(?:LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT|UNLICENSE)(?:[-_.].*)?\Z", re.I)
HEX = re.compile(r"[0-9a-f]{64}\Z")
RING_REQUIRED = ("LICENSE", "LICENSE-other-bits", "LICENSE-BoringSSL",
                 "third_party/fiat/LICENSE", "src/polyfill/once_cell/LICENSE-APACHE",
                 "src/polyfill/once_cell/LICENSE-MIT")
WEBPKI_REQUIRED = ("src/crl/mod.rs", "src/subject_name/mod.rs")
WORKSPACE_TARGETS = ("x86_64-unknown-linux-musl", "x86_64-unknown-linux-gnu",
                     "x86_64-pc-windows-msvc")
# These published leaf crates omit standalone license files. Their sibling
# packages carry byte-for-byte copies of the license files at the exact
# upstream revisions recorded by the omitted crates' .cargo_vcs_info.json.
# The expected hashes also match the pinned upstream repository files.
REVIEWED_SIBLINGS = {
    ("asn1-rs-impl", "0.2.0"): ("asn1-rs", "0.7.1", {
        "LICENSE-APACHE": "a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2",
        "LICENSE-MIT": "a5c61b93b6ee1d104af9920cf020ff3c7efe818e31fe562c72261847a728f513",
    }, "a20e5f7319c896737ad0f2557037817b91ad854f"),
    ("tonic-prost", "0.14.5"): ("tonic", "0.14.5", {
        "LICENSE": "e24a56698aa6feaf3a02272b3624f9dc255d982970c5ed97ac4525a95056a5b3",
    }, "21d24942a5a4a1806344beb331d4157d510a210c"),
    ("tonic-prost-build", "0.14.5"): ("tonic", "0.14.5", {
        "LICENSE": "e24a56698aa6feaf3a02272b3624f9dc255d982970c5ed97ac4525a95056a5b3",
    }, "21d24942a5a4a1806344beb331d4157d510a210c"),
}


def safe_upstream_relative(path: str) -> bool:
    """Allow ordinary dotfiles in published crates, while rejecting traversal."""
    return (bool(path) and not path.startswith("/") and "\\" not in path and
            not any(ord(char) < 32 or ord(char) == 127 for char in path) and
            all(part not in ("", ".", "..") for part in path.split("/")))


def dependency_archive_entries(archive: Path, name: str, version: str) -> dict[str, bytes]:
    """Read a verified registry crate without project-package layout assumptions."""
    prefix = f"{name}-{version}/"
    require(archive.is_file() and not archive.is_symlink() and archive.stat().st_size <= 72 * 1024 * 1024,
            f"missing or oversized dependency archive: {archive}")
    entries = {}
    total = 0
    try:
        with tarfile.open(archive, "r:gz") as package:
            for member in package:
                require(member.name.startswith(prefix), f"dependency archive path outside root: {member.name}")
                relative = member.name[len(prefix):].rstrip("/")
                require(safe_upstream_relative(relative), f"unsafe dependency archive path: {member.name}")
                require(not member.issym() and not member.islnk() and not member.linkname,
                        f"linked dependency archive member: {member.name}")
                if member.isdir():
                    require(member.size == 0, f"dependency archive directory has content: {member.name}")
                    continue
                require(member.isfile() and member.size <= 16 * 1024 * 1024 and
                        relative not in entries and len(entries) < 1000,
                        f"invalid dependency archive member: {member.name}")
                total += member.size
                require(total <= 64 * 1024 * 1024, f"dependency archive content too large: {archive}")
                reader = package.extractfile(member)
                require(reader is not None, f"unreadable dependency archive member: {member.name}")
                data = reader.read(member.size + 1)
                require(len(data) == member.size, f"dependency archive member size differs: {member.name}")
                entries[relative] = data
    except (OSError, tarfile.TarError) as exc:
        raise ReleaseError(f"cannot read dependency archive {archive}: {exc}") from exc
    return entries


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_hash(path: Path) -> str:
    return _sha(path.read_bytes())


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise ReleaseError(f"cannot read {path}: {exc}") from exc
    require(isinstance(data, dict), f"invalid object in {path}")
    return data


def _header(data: bytes) -> bytes | None:
    """Return a verbatim leading copyright comment, without source code."""
    lines = data.splitlines(keepends=True)
    if not lines:
        return None
    head = []
    for line in lines[:80]:
        stripped = line.lstrip()
        if stripped.startswith((b"//", b"/*", b"*", b"#")) or not stripped.strip():
            head.append(line)
            continue
        break
    block = b"".join(head)
    if b"copyright" not in block.lower():
        return None
    require(len(block) <= 8192, "upstream copyright header is unexpectedly large")
    return block.rstrip() + b"\n"


def collect_material(name: str, version: str, entries: dict[str, bytes],
                     reviewed_sibling: dict[str, bytes] | None = None) -> dict[str, bytes]:
    """Select exact upstream license files and per-file copyright headers.

    ring's reviewed 0.17.14 source is copied in full as a conservative
    supplement because its ISC and BoringSSL notices are distributed among
    many source files, including bundled C and assembly. This is not an
    assertion that every included source file is linked into every artifact.
    """
    require(isinstance(entries, dict) and entries, f"empty upstream archive: {name} {version}")
    for relative, data in entries.items():
        require(isinstance(relative, str) and safe_upstream_relative(relative) and isinstance(data, bytes),
                f"unsafe upstream material path: {relative}")
    material = {}
    for relative, data in sorted(entries.items()):
        if LICENSE_NAME.fullmatch(Path(relative).name):
            require(data.strip(), f"empty upstream license material: {name} {version}/{relative}")
            material[f"licenses/{relative}"] = data
        if relative.endswith((".rs", ".c", ".h", ".S", ".s")):
            header = _header(data)
            if header:
                material[f"headers/{relative}.txt"] = header
    if reviewed_sibling is not None:
        require(not any(path.startswith("licenses/") for path in material),
                f"unexpected license fallback for {name} {version}")
        for relative, data in sorted(reviewed_sibling.items()):
            require(safe_upstream_relative(relative) and data.strip(),
                    f"empty or unsafe reviewed sibling license: {relative}")
            material[f"licenses-from-reviewed-sibling/{relative}"] = data
    require(any(path.startswith(("licenses/", "licenses-from-reviewed-sibling/")) for path in material),
            f"missing upstream license material: {name} {version}")
    if name == "ring":
        require(version == "0.17.14", "ring subcomponent review requires refresh for a new version")
        for relative in RING_REQUIRED:
            require(entries.get(relative, b"").strip(), f"ring subcomponent material missing: {relative}")
        for relative, data in sorted(entries.items()):
            if relative != ".cargo_vcs_info.json":
                material[f"source-supplement/{relative}"] = data
    if name == "rustls-webpki":
        require(version == "0.103.15", "rustls-webpki notice review requires refresh for a new version")
        lib = entries.get("src/lib.rs", b"")
        require(b"mod crl" in lib and b"mod subject_name" in lib,
                "rustls-webpki production module scope changed")
        for relative in WEBPKI_REQUIRED:
            require(relative in entries and f"headers/{relative}.txt" in material,
                    f"rustls-webpki compiled file notice missing: {relative}")
        # This version's Chromium include and DNS test cases are cfg(test).
        # Verify the source topology rather than assuming a missing fixture
        # directory is harmless for every future published archive.
        alg_tests = entries.get("src/alg_tests.rs", b"")
        dns = entries.get("src/subject_name/dns_name.rs", b"")
        require(b"third-party/chromium/data/verify_signed_data/" in alg_tests,
                "rustls-webpki Chromium test fixture reference changed")
        for variant in ("ring_algs", "aws_lc_rs_algs"):
            source = entries.get(f"src/{variant}.rs", b"")
            require(re.search(rb'#\[cfg\(test\)\]\s*#\[path = "\."\]\s*mod tests\s*\{', source) and
                    re.search(rb'#\[path = "alg_tests\.rs"\]\s*mod alg_tests;', source),
                    f"rustls-webpki {variant} Chromium test scope changed")
        require(re.search(rb'#\[cfg\(test\)\]\s*mod tests\s*\{', dns) and
                b"adapted from Chromium" in dns,
                "rustls-webpki Chromium DNS test scope changed")
        # Do not copy test source or claim a Chromium obligation for normal builds.
        require(b"third-party/chromium" not in lib,
                "rustls-webpki Chromium source scope requires review")
    return material


def _lock_packages(path: Path) -> dict[tuple[str, str], str]:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseError(f"cannot read build lock {path}: {exc}") from exc
    output = {}
    for package in raw.get("package", []):
        if package.get("source") == "registry+https://github.com/rust-lang/crates.io-index":
            key = (package["name"], package["version"])
            checksum = package.get("checksum")
            require(isinstance(checksum, str) and HEX.fullmatch(checksum),
                    f"missing lock checksum: {key}")
            require(key not in output, f"duplicate locked dependency: {key}")
            output[key] = checksum
    return output


def verified_dependency_archive(name: str, version: str, manifest: Path, cargo_home: Path,
                                locks: dict[str, dict[tuple[str, str], str]],
                                scopes: dict[str, set[str]]) -> tuple[Path, str]:
    """Bind a registry dependency to its exact locked cached .crate bytes."""
    manifest, cargo_home = Path(manifest), Path(cargo_home)
    require(manifest.name == "Cargo.toml" and manifest.parent.name == f"{name}-{version}" and
            manifest.is_file() and not manifest.is_symlink() and
            manifest.is_relative_to(cargo_home / "registry/src") and
            manifest.resolve().is_relative_to((cargo_home / "registry/src").resolve()),
            f"dependency source path is unsafe: {manifest}")
    index = manifest.parent.parent.name
    expected = {values[(name, version)] for root, values in locks.items()
                if (name, version) in values and root in scopes}
    require(len(expected) == 1, f"dependency lock checksum differs: {name} {version}")
    checksum = expected.pop()
    archive = cargo_home / "registry/cache" / index / f"{name}-{version}.crate"
    require(archive.is_file() and not archive.is_symlink() and
            _file_hash(archive) == checksum,
            f"dependency archive checksum differs: {name} {version}")
    return archive, checksum


def _node_scopes(metadata: dict, root: str, include_dev: bool) -> dict[tuple[str, str, str], set[str]]:
    packages = {item["id"]: item for item in metadata.get("packages", [])}
    nodes = {item["id"]: item for item in metadata.get("resolve", {}).get("nodes", [])}
    roots = [item["id"] for item in packages.values() if item["name"] == root]
    require(len(roots) == 1, f"{root} metadata root is ambiguous")
    pending = [(roots[0], "runtime")]
    seen = set()
    scopes = {}
    while pending:
        item_id, scope = pending.pop()
        if (item_id, scope) in seen:
            continue
        seen.add((item_id, scope))
        require(item_id in packages and item_id in nodes, f"metadata node missing: {item_id}")
        item = packages[item_id]
        identity = (item["name"], item["version"], item.get("source") or "verified-unpacked-root")
        scopes.setdefault(identity, set()).add(scope)
        for dep in nodes[item_id].get("deps", []):
            require(dep.get("pkg") in packages, f"metadata dependency missing: {dep}")
            for kind in dep.get("dep_kinds", []):
                edge = kind.get("kind")
                if edge is None or edge == "build" or (edge == "dev" and include_dev):
                    child_scope = ("example/dev" if edge == "dev" or scope == "example/dev" else
                                   "build" if edge == "build" or scope == "build" else "runtime")
                    pending.append((dep["pkg"], child_scope))
    return scopes


def _workspace_entries(root: Path) -> dict[str, bytes]:
    require(root.is_dir() and not root.is_symlink(), f"workspace crate root missing: {root}")
    entries = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), f"workspace crate contains a linked file: {path}")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            require(safe_upstream_relative(relative) and path.stat().st_size <= 16 * 1024 * 1024,
                    f"unsafe workspace source: {path}")
            entries[relative] = path.read_bytes()
    require("Cargo.toml" in entries, f"workspace manifest missing: {root}")
    return entries


def _workspace_content_hash(entries: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for relative, data in sorted(entries.items()):
        digest.update(relative.encode() + b"\0" + data + b"\0")
    return digest.hexdigest()


def workspace_feature_tree(repo: Path, target: str) -> tuple[dict[str, set[str]], set[tuple[str, str]]]:
    """Capture the unified normal/build graph of one `cargo build --workspace`."""
    command = ["cargo", "tree", "--locked", "--offline", "--target", target,
               "--workspace", "-e", "normal,build", "--prefix", "none", "-f", "{p}|{f}"]
    result = subprocess.run(command, cwd=repo, text=True, capture_output=True)
    require(result.returncode == 0,
            f"workspace feature tree failed: {result.stderr[-2000:]}")
    features = {}
    packages = set()
    for line in result.stdout.splitlines():
        if not line:
            continue
        package, separator, enabled = line.partition("|")
        require(separator == "|" and " v" in package, f"invalid workspace feature tree: {line}")
        name, version_text = package.split(" v", 1)
        version = version_text.split()[0]
        packages.add((name, version))
        features.setdefault(name, set()).update(enabled.removesuffix(" (*)").split(",") if enabled else ())
    require(packages, "empty workspace feature tree")
    return features, packages


def collect_workspace_inputs(repo: Path, binaries_dir: Path, target: str, output: Path) -> Path:
    """Record an actual OS package build as local workspace input, never registry evidence."""
    repo, binaries_dir, output = map(Path, (repo, binaries_dir, output))
    require(target in WORKSPACE_TARGETS, f"unsupported workspace package target: {target}")
    require(not output.exists() and not output.is_symlink(), "workspace input output already exists")
    require(binaries_dir.is_dir(), "workspace binaries directory is absent")
    if target == TARGETS[1]:
        names = {"pkcs11-proxy-ng.exe": ("pkcs11-proxy-ng", "bin"),
                 "pkcs11-proxy-ng-cli.exe": ("pkcs11-proxy-ng-cli", "bin"),
                 "pkcs11_proxy_ng_shim.dll": ("pkcs11-proxy-ng-shim", "lib"),
                 "cross_width_smoke.exe": ("pkcs11-proxy-ng-shim", "example")}
    else:
        names = {"pkcs11-proxy-ng": ("pkcs11-proxy-ng", "bin"),
                 "pkcs11-proxy-ng-cli": ("pkcs11-proxy-ng-cli", "bin"),
                 "libpkcs11_proxy_ng_shim.so": ("pkcs11-proxy-ng-shim", "lib")}
    require(all((binaries_dir / name).is_file() and not (binaries_dir / name).is_symlink()
                for name in names), "workspace package binaries are incomplete")

    def cargo_output(command: list[str]) -> str:
        result = subprocess.run(command, cwd=repo, text=True, capture_output=True)
        require(result.returncode == 0,
                f"workspace notice command failed {' '.join(command)}: {result.stderr[-2000:]}")
        return result.stdout.strip()

    versions = {"rustc": cargo_output(["rustc", "--version"]),
                "cargo": cargo_output(["cargo", "--version"]),
                "protoc": cargo_output(["protoc", "--version"])}
    require(versions["rustc"].startswith("rustc 1.98.1 ") and
            versions["cargo"].startswith("cargo 1.98.1 "),
            "workspace notice toolchain differs from package build pin")
    sysroot = cargo_output(["rustc", "--print", "sysroot"])
    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))).resolve()
    metadata = json.loads(cargo_output(["cargo", "metadata", "--locked", "--format-version", "1",
                                        "--filter-platform", target]))
    unified_features, unified_packages = workspace_feature_tree(repo, target)
    manifest = tomllib.loads((repo / "Cargo.toml").read_text(encoding="utf-8"))
    version = manifest["workspace"]["package"]["version"]
    graphs = {}
    for root in ROOTS:
        scopes = _node_scopes(metadata, root, False)
        tree_packages = {(name, package_version) for name, package_version, _ in scopes}
        tree_packages &= unified_packages
        require((root, version) in tree_packages and
                all(name in unified_features for name, _ in tree_packages),
                f"workspace unified feature closure differs: {root}")
        features = {name: unified_features[name] for name, _ in tree_packages}
        sources = []
        for name, package_version, source in sorted(scopes):
            if (name, package_version) in tree_packages:
                sources.append({"name": name, "version": package_version,
                                "source": "workspace-local" if name in INTERNAL else source})
        graphs[root] = {"metadata": metadata,
                        "runtime_features": {key: sorted(value) for key, value in features.items()},
                        "tree_packages": sorted([list(item) for item in tree_packages]),
                        "resolved_sources": sources,
                        "lock_path": str((repo / "Cargo.lock").resolve()),
                        "original_lock_path": str((repo / "Cargo.lock").resolve())}
    artifacts = []
    for name, (package, kind) in names.items():
        path = binaries_dir / name
        artifacts.append({"name": name, "package": package, "kind": kind,
                          "sha256": _file_hash(path), "size": path.stat().st_size})
    output.mkdir(parents=True, exist_ok=False)
    prepared = output / "binaries"
    prepared.mkdir()
    for name in names:
        shutil.copyfile(binaries_dir / name, prepared / name)
    inputs = {"format_version": 1, "source_mode": "workspace", "target": target,
              "feature_scope": "cargo-build-workspace-unified-default",
              "cargo_home": str(cargo_home), "rust_sysroot": sysroot,
              "workspace_lock_path": str((repo / "Cargo.lock").resolve()),
              "source_roots": {name: str((repo / "crates" / directory).resolve())
                               for name, directory in PACKAGES},
              "graphs": graphs}
    provenance = {"format_version": 1, "source_mode": "workspace",
                  "feature_scope": "cargo-build-workspace-unified-default",
                  "github_publication_eligible": False, "version": version,
                  "source_commit": "workspace-source-unverified", "target": target,
                  "tools": versions, "workspace_lock_sha256": _file_hash(repo / "Cargo.lock"),
                  "artifacts": artifacts,
                  "graphs": {name: {"resolved_sources": graph["resolved_sources"],
                                    "runtime_features": graph["runtime_features"],
                                    "tree_packages": graph["tree_packages"]}
                             for name, graph in graphs.items()}}
    (output / "build-inputs.json").write_text(json.dumps(inputs, indent=2, sort_keys=True) + "\n")
    (output / "build-provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    return output / "build-inputs.json"


def _checked_inputs(path: Path) -> tuple[dict, dict, dict]:
    """Validate supplied source identities without consulting the later checkout HEAD."""
    inputs = _read_json(path)
    provenance_path = path.parent / "build-provenance.json"
    provenance = _read_json(provenance_path)
    require(inputs.get("format_version") == provenance.get("format_version") == 1 and
            inputs.get("source_mode") == provenance.get("source_mode") and
            inputs.get("target") == provenance.get("target") and
            provenance.get("target") in TARGETS + WORKSPACE_TARGETS,
            "notice build inputs and portable provenance differ")
    mode = inputs["source_mode"]
    require(mode in ("archive", "registry", "workspace"), "unsupported notice input source mode")
    if mode == "workspace":
        require(provenance.get("github_publication_eligible") is False and
                provenance.get("source_commit") == "workspace-source-unverified" and
                inputs.get("feature_scope") == provenance.get("feature_scope") ==
                "cargo-build-workspace-unified-default" and
                set(inputs.get("source_roots", {})) == INTERNAL and
                set(inputs.get("graphs", {})) == set(ROOTS) and
                provenance.get("workspace_lock_sha256") ==
                _file_hash(Path(inputs["workspace_lock_path"])),
                "workspace notices require local source and lock identity")
        for name in ROOTS:
            local = inputs["graphs"][name]
            portable = provenance["graphs"][name]
            require(local["resolved_sources"] == portable["resolved_sources"] and
                    local["runtime_features"] == portable["runtime_features"] and
                    local["tree_packages"] == portable["tree_packages"] and
                    _file_hash(Path(local["lock_path"])) == provenance["workspace_lock_sha256"] and
                    set(map(tuple, local["tree_packages"])) ==
                    {(item["name"], item["version"]) for item in portable["resolved_sources"]},
                    f"workspace dependency closure differs: {name}")
        binaries = path.parent / "binaries"
        artifacts = provenance.get("artifacts", [])
        require(binaries.is_dir() and {item.name for item in binaries.iterdir()} ==
                {item["name"] for item in artifacts}, "workspace binary set differs")
        for item in artifacts:
            binary = binaries / item["name"]
            require(binary.is_file() and not binary.is_symlink() and
                    binary.stat().st_size == item["size"] > 0 and
                    _file_hash(binary) == item["sha256"],
                    f"workspace binary differs: {item['name']}")
        rust_notice = Path(inputs["rust_sysroot"]) / "share/doc/rust/COPYRIGHT-library.html"
        require(rust_notice.is_file() and not rust_notice.is_symlink() and rust_notice.stat().st_size,
                f"Rust standard library notice is missing: {rust_notice}")
        require(provenance.get("tools", {}).get("rustc", "").startswith("rustc 1.98.1 "),
                "workspace notice compiler differs")
        return inputs, provenance, {"version": provenance["version"], "packages": []}
    inventory_path = Path(inputs.get("inventory_path", ""))
    package_dir = Path(inputs.get("package_dir", ""))
    inventory = read_inventory(inventory_path)
    require(provenance.get("inventory_sha256") == _file_hash(inventory_path) and
            provenance.get("source_commit") == inventory.get("source_commit") and
            provenance.get("version") == inventory.get("version") and
            {item["name"]: item["sha256"] for item in inventory["packages"]} == provenance.get("archives"),
            "notice source inventory differs from binary provenance")
    require(set(inputs.get("archive_paths", {})) == set(provenance["archives"]) and
            set(inputs.get("source_roots", {})) == set(provenance["archives"]),
            "notice source archive/root set is incomplete")
    for item in inventory["packages"]:
        name = item["name"]
        archive = Path(inputs["archive_paths"][name])
        require(archive.is_file() and not archive.is_symlink() and
                archive.resolve().parent == package_dir.resolve() and
                archive.name == item["archive"] and _file_hash(archive) == item["sha256"],
                f"notice source archive differs: {name}")
        entries = archive_entries(archive, name, inventory["version"])
        require(_sha(entries["Cargo.lock"]) == provenance["original_locks"][name],
                f"notice original lock differs: {name}")
    if mode == "registry":
        require_registry_provenance(provenance_path, inventory_path, package_dir,
                                    path.parent / "binaries")
    else:
        require(provenance.get("github_publication_eligible") is False,
                "candidate notices cannot claim registry publication")
    require(set(inputs.get("graphs", {})) == set(ROOTS) == set(provenance.get("graphs", {})),
            "notice build graphs are incomplete")
    for name in ROOTS:
        local = inputs["graphs"][name]
        portable = provenance["graphs"][name]
        require(local.get("checked", {}).get("resolved_sources") == portable.get("resolved_sources") and
                local.get("runtime_features") == portable.get("runtime_features") and
                local.get("checked", {}).get("packages") == portable.get("packages") and
                _file_hash(Path(local["original_lock_path"])) == provenance["original_locks"][name] and
                _file_hash(Path(local["lock_path"])) == provenance["effective_locks"][name],
                f"notice dependency graph or lock differs: {name}")
        checked = validate_build_graph(
            local["metadata"], path.parent / "unpacked", name, inventory["version"], mode,
            {key: set(value) for key, value in local["runtime_features"].items()})
        require(checked == local["checked"], f"notice source graph validation differs: {name}")
        scopes = _node_scopes(local["metadata"], name, False)
        expected = {(item["name"], item["version"]) for item in portable["resolved_sources"]}
        require({(key[0], key[1]) for key in scopes} == expected,
                f"notice graph closure differs: {name}")
    expected_artifacts = {item["name"]: item for item in provenance.get("artifacts", [])}
    binaries = path.parent / "binaries"
    require(expected_artifacts and binaries.is_dir() and
            {p.name for p in binaries.iterdir()} == set(expected_artifacts),
            "notice binaries differ from provenance")
    for name, item in expected_artifacts.items():
        binary = binaries / name
        require(binary.is_file() and not binary.is_symlink() and
                binary.stat().st_size == item.get("size") and _file_hash(binary) == item.get("sha256"),
                f"notice binary differs: {name}")
    sysroot = Path(inputs.get("rust_sysroot", ""))
    rust_notice = sysroot / "share/doc/rust/COPYRIGHT-library.html"
    require(rust_notice.is_file() and not rust_notice.is_symlink() and rust_notice.stat().st_size,
            f"Rust standard library notice is missing: {rust_notice}")
    require(str(provenance.get("tools", {}).get("rustc", "")).startswith("rustc 1.98.1 "),
            "notice toolchain differs from binary compiler")
    return inputs, provenance, inventory


def generate_notices(build_inputs_path: Path, output: Path) -> dict:
    """Write readable notices and an exact file/input hash inventory."""
    build_inputs_path, output = Path(build_inputs_path), Path(output)
    inputs, provenance, inventory = _checked_inputs(build_inputs_path)
    require(not output.exists() and not output.is_symlink(), "notice output already exists")
    cargo_home = Path(inputs["cargo_home"])
    root_scopes = {}
    for root in ROOTS:
        local = inputs["graphs"][root]
        scopes = _node_scopes(local["metadata"], root, False)
        tree_packages = (set(map(tuple, local["tree_packages"])) if provenance["source_mode"] == "workspace"
                         else None)
        for identity, labels in scopes.items():
            if tree_packages is not None and identity[:2] not in tree_packages:
                continue
            key = identity[:2]
            root_scopes.setdefault(key, {}).setdefault(root, set()).update(labels)
        if inputs["target"] == TARGETS[1] and root == "pkcs11-proxy-ng-shim":
            extra = _node_scopes(local["metadata"], root, True)
            for identity, labels in extra.items():
                if "example/dev" in labels:
                    root_scopes.setdefault(identity[:2], {}).setdefault("cross_width_smoke.exe", set()).add(
                        "example/dev")
    metadata_packages = {}
    for root in ROOTS:
        for item in inputs["graphs"][root]["metadata"]["packages"]:
            metadata_packages.setdefault((item["name"], item["version"]), item)
    files = {}
    records = []
    locks = {root: _lock_packages(Path(inputs["graphs"][root]["original_lock_path"])) for root in ROOTS}
    internal_records = {item["name"]: item for item in inventory["packages"]}
    source_entries = {}
    for (name, version), scopes in sorted(root_scopes.items()):
        package = metadata_packages[(name, version)]
        if name in INTERNAL:
            require(version == inventory["version"], f"internal notice version differs: {name}")
            if provenance["source_mode"] == "workspace":
                entries = _workspace_entries(Path(inputs["source_roots"][name]))
                source_hash = _workspace_content_hash(entries)
            else:
                archive = Path(inputs["archive_paths"][name])
                source_hash = internal_records[name]["sha256"]
                entries = archive_entries(archive, name, version)
        else:
            manifest = Path(package["manifest_path"])
            archive, source_hash = verified_dependency_archive(
                name, version, manifest, cargo_home, locks, scopes)
            entries = dependency_archive_entries(archive, name, version)
        source_entries[(name, version)] = entries
        fallback = None
        fallback_record = None
        if (name, version) in REVIEWED_SIBLINGS:
            donor_name, donor_version, expected_hashes, revision = REVIEWED_SIBLINGS[(name, version)]
            donor = source_entries.get((donor_name, donor_version))
            require(donor is not None and (donor_name, donor_version) in root_scopes,
                    f"reviewed license donor is absent: {donor_name} {donor_version}")
            vcs = json.loads(entries.get(".cargo_vcs_info.json", b"{}"))
            require(vcs.get("git", {}).get("sha1") == revision,
                    f"reviewed license source revision differs: {name} {version}")
            fallback = {}
            for relative, expected_hash in expected_hashes.items():
                data = donor.get(relative, b"")
                require(data.strip() and _sha(data) == expected_hash,
                        f"reviewed license donor material differs: {donor_name}/{relative}")
                fallback[relative] = data
            fallback_record = {"donor": f"{donor_name} {donor_version}",
                               "upstream_revision": revision,
                               "license_sha256": expected_hashes}
        material = collect_material(name, version, entries, fallback)
        prefix = f"license-material/{name}-{version}"
        material_paths = []
        for relative, data in sorted(material.items()):
            path = f"{prefix}/{relative}"
            require(path not in files, f"duplicate notice material: {path}")
            files[path] = data
            material_paths.append(path)
        records.append({"name": name, "version": version, "source_sha256": source_hash,
                        "license": package.get("license"),
                        "reviewed_sibling_license": fallback_record,
                        "scopes": {root: sorted(labels) for root, labels in sorted(scopes.items())},
                        "material": material_paths})
    rust_notice = Path(inputs["rust_sysroot"]) / "share/doc/rust/COPYRIGHT-library.html"
    files["license-material/rust-std/COPYRIGHT-library.html"] = rust_notice.read_bytes()
    rust_record = {"version": provenance["tools"]["rustc"],
                   "sha256": _file_hash(rust_notice),
                   "material": "license-material/rust-std/COPYRIGHT-library.html"}
    source_label = {"archive": "archive candidate; not a registry publication",
                    "registry": "verified registry archives",
                    "workspace": "local workspace build; not registry-source evidence"}[provenance["source_mode"]]
    lines = ["THIRD-PARTY NOTICES FOR PKCS11-PROXY-NG", "",
             f"Source mode: {provenance['source_mode']} ({source_label})",
             f"Source commit: {provenance['source_commit']}", f"Target: {provenance['target']}",
             "", "This is an engineering attribution inventory, not legal clearance.",
             "Dependency scopes describe Cargo target/feature closures, not proof that every object is linked.",
             "Build, example/dev and conservative-extra material is labeled separately.", "",
             "Rust standard library:", f"  {rust_record['version']}",
             f"  {rust_record['material']} (SHA-256 {rust_record['sha256']})", ""]
    if provenance["source_mode"] == "workspace":
        lines.extend(["Workspace package build: default features are unified across all eight members.",
                      "Per-root scopes describe metadata reachability within that shared build, not isolated builds.", ""])
    for record in records:
        lines.append(f"{record['name']} {record['version']} [{record['license'] or 'license-file'}]")
        lines.append(f"  source SHA-256: {record['source_sha256']}")
        for root, labels in record["scopes"].items():
            lines.append(f"  {root}: {', '.join(labels)}")
        if record["name"] == "ring":
            lines.append("  conservative-extra: full pinned source supplement preserves per-file ISC/BoringSSL notices")
        if record["name"] == "rustls-webpki":
            lines.append("  Chromium test fixtures/references are cfg(test) in this published version; normal dependency builds exclude them")
        if record["reviewed_sibling_license"]:
            lines.append("  reviewed sibling license source: " + record["reviewed_sibling_license"]["donor"] +
                         " at upstream revision " + record["reviewed_sibling_license"]["upstream_revision"])
        for material_path in record["material"]:
            lines.append(f"  {material_path}")
        lines.append("")
    files["THIRD_PARTY_NOTICES"] = ("\n".join(lines) + "\n").encode()
    output.mkdir(parents=True, exist_ok=False)
    for relative, data in sorted(files.items()):
        dest = output / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    inventory_record = {"format_version": 1, "source_mode": provenance["source_mode"],
                        "source_commit": provenance["source_commit"], "target": provenance["target"],
                        "build_inputs_sha256": _file_hash(build_inputs_path),
                        "build_provenance_sha256": _file_hash(build_inputs_path.parent / "build-provenance.json"),
                        "source_inventory_sha256": (_file_hash(Path(inputs["inventory_path"]))
                                                    if provenance["source_mode"] != "workspace" else None),
                        "tools": provenance["tools"], "rust_std": rust_record,
                        "artifacts": provenance["artifacts"], "packages": records,
                        "files": {name: _sha(data) for name, data in sorted(files.items())}}
    (output / "notice-inventory.json").write_text(
        json.dumps(inventory_record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return inventory_record

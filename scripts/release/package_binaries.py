"""Build release binaries from checksum-bound published or candidate crate sources."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import shutil
import subprocess
import tomllib

from .package_archives import archive_entries, extract_verified_archives, inspect_archives
from .package_consumers import (_external_lock, _patches, _seed_lock, reconcile_lock,
                                validate_metadata, validate_version_line, REGISTRY_SOURCE, _shim_exports)
from .package_model import INTERNAL, PACKAGES, ReleaseError, require
from .package_registry import Registry, read_inventory, verify_publication


TARGETS = ("x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc")
TOOLCHAIN = "1.98.1"
XWIN_VERSION = "cargo-xwin-xwin 0.23.1"
ROOTS = ("pkcs11-proxy-ng", "pkcs11-proxy-ng-cli", "pkcs11-proxy-ng-shim")


def validate_release_profile(repo: Path) -> None:
    profile = tomllib.loads((Path(repo) / "Cargo.toml").read_text(encoding="utf-8")).get(
        "profile", {}).get("release", {})
    require(profile.get("lto") == "thin" and profile.get("strip") == "symbols" and
            profile.get("codegen-units") == 1 and profile.get("panic", "unwind") == "unwind",
            "workspace release profile differs from recorded unwind/thin-LTO profile")


def require_registry_provenance(path: Path, inventory_path: Path,
                                package_dir: Path, binaries_dir: Path) -> dict:
    """Bind a registry build claim to exact source archives and staged files.

    Callers must separately enforce the publication/approval gates. The
    package directory is the downloaded, checksum-verified source set used by
    the binary build, and the binary directory is the set proposed for upload.
    """
    try:
        provenance = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise ReleaseError(f"cannot read binary provenance {path}: {exc}") from exc
    require(isinstance(provenance, dict) and provenance.get("format_version") == 1 and
            provenance.get("source_mode") == "registry" and
            provenance.get("github_publication_eligible") is True,
            "GitHub publication requires registry-source binary provenance")
    inventory = read_inventory(inventory_path)
    require(provenance.get("version") == inventory["version"] and
            provenance.get("source_commit") == inventory["source_commit"] and
            provenance.get("inventory_sha256") == _sha256(Path(inventory_path)),
            "binary provenance source identity differs from inventory")
    tag = provenance.get("source_tag")
    require(tag is None or (isinstance(tag, dict) and
            tag.get("name") == f"v{inventory['version']}" and
            isinstance(tag.get("object_sha"), str) and
            re.fullmatch(r"[0-9a-f]{40}", tag["object_sha"]) is not None),
            "binary provenance source tag is malformed")
    target = provenance.get("target")
    require(target in TARGETS, "binary provenance target is unsupported")
    expected_names = {name for name, _ in PACKAGES}
    archive_hashes = provenance.get("archives")
    locks = provenance.get("original_locks")
    require(isinstance(archive_hashes, dict) and set(archive_hashes) == expected_names and
            isinstance(locks, dict) and set(locks) == expected_names,
            "binary provenance lacks all-eight archive and lock identities")
    package_dir = Path(package_dir)
    require(package_dir.is_dir() and
            {item.name for item in package_dir.glob("*.crate")} ==
            {record["archive"] for record in inventory["packages"]},
            "binary evidence archive directory differs from inventory")
    for record in inventory["packages"]:
        name = record["name"]
        archive = package_dir / record["archive"]
        require(archive.is_file() and not archive.is_symlink() and
                _sha256(archive) == record["sha256"] == archive_hashes[name],
                f"{name} binary provenance archive checksum differs")
        entries = archive_entries(archive, name, inventory["version"])
        require("Cargo.lock" in entries and
                hashlib.sha256(entries["Cargo.lock"]).hexdigest() == locks[name],
                f"{name} binary provenance packaged lock differs")
    tools = provenance.get("tools")
    require(isinstance(tools, dict) and
            isinstance(tools.get("rustc"), str) and tools["rustc"].startswith(f"rustc {TOOLCHAIN} ") and
            isinstance(tools.get("cargo"), str) and tools["cargo"].startswith(f"cargo {TOOLCHAIN} ") and
            isinstance(tools.get("protoc"), str) and tools["protoc"].startswith("libprotoc "),
            "binary provenance tool versions are incomplete or wrong")
    if target == TARGETS[1]:
        require(tools.get("cargo_xwin") == XWIN_VERSION,
                "Windows binary provenance cargo-xwin version differs")
    profile = provenance.get("profile")
    require(profile == {"name": "release", "lto": "thin", "strip": "symbols",
                        "codegen_units": 1, "panic": "unwind", "incremental": False, "jobs": 4} and
            provenance.get("flags") == {"rustflags": [], "rustdocflags": []},
            "binary provenance release profile or flags differ")
    graphs = provenance.get("graphs")
    require(isinstance(graphs, dict) and set(graphs) == set(ROOTS),
            "binary provenance entry-point graphs are incomplete")
    effective_locks = provenance.get("effective_locks")
    require(isinstance(effective_locks, dict) and set(effective_locks) == set(ROOTS) and
            all(effective_locks[name] == locks[name] for name in ROOTS),
            "registry binary provenance effective locks differ from packaged locks")
    for name, graph in graphs.items():
        require(isinstance(graph, dict) and isinstance(graph.get("packages"), list) and
                name in graph["packages"] and
                isinstance(graph.get("runtime_features"), dict) and
                name in graph["runtime_features"],
                f"{name} binary provenance graph is incomplete")
        sources = graph.get("resolved_sources")
        require(isinstance(sources, list) and sources and
                all(isinstance(item, dict) and set(item) == {"name", "version", "source"} and
                    isinstance(item["name"], str) and isinstance(item["version"], str)
                    for item in sources),
                f"{name} binary provenance resolved sources are incomplete")
        require(len({(item["name"], item["version"], item["source"]) for item in sources}) == len(sources),
                f"{name} binary provenance resolved sources repeat an identity")
        roots = [item for item in sources if item["name"] == name]
        require(len(roots) == 1 and roots[0] == {"name": name, "version": inventory["version"],
                                                  "source": "verified-unpacked-root"},
                f"{name} binary provenance root source differs")
        for item in sources:
            if item["name"] != name:
                require(item["source"] == REGISTRY_SOURCE and
                        (item["name"] not in INTERNAL or item["version"] == inventory["version"]),
                        f"{name} binary provenance includes a non-registry dependency")
        require(set(graph["packages"]) == {item["name"] for item in sources
                                             if item["name"] in INTERNAL},
                f"{name} binary provenance internal source graph differs")
    expected_artifacts = {"pkcs11-proxy-ng": ("pkcs11-proxy-ng", "bin"),
                          "pkcs11-proxy-ng-cli": ("pkcs11-proxy-ng-cli", "bin"),
                          _artifact_name("pkcs11-proxy-ng-shim", target): ("pkcs11-proxy-ng-shim", "lib")}
    if target == TARGETS[1]:
        expected_artifacts = {name + ".exe" if kind == "bin" else name: value
                              for name, value in expected_artifacts.items() for kind in [value[1]]}
        expected_artifacts["cross_width_smoke.exe"] = ("pkcs11-proxy-ng-shim", "example")
    records = provenance.get("artifacts")
    require(isinstance(records, list) and len(records) == len(expected_artifacts) and
            all(isinstance(record, dict) for record in records),
            "binary provenance artifact set is incomplete")
    by_name = {record.get("name"): record for record in records}
    require(set(by_name) == set(expected_artifacts) and len(by_name) == len(records),
            "binary provenance artifact names differ")
    binaries_dir = Path(binaries_dir)
    require(binaries_dir.is_dir() and
            {item.name for item in binaries_dir.iterdir()} == set(expected_artifacts),
            "staged binary set differs from provenance")
    for name, (package, kind) in expected_artifacts.items():
        record = by_name[name]
        binary = binaries_dir / name
        require(binary.is_file() and not binary.is_symlink() and
                record.get("package") == package and record.get("kind") == kind and
                isinstance(record.get("size"), int) and not isinstance(record["size"], bool) and
                record["size"] > 0 and binary.stat().st_size == record["size"] and
                record.get("sha256") == _sha256(binary),
                f"{name} staged binary differs from provenance")
    return provenance


def release_environment(root: Path, target: str, inherited: dict | None = None) -> dict:
    """Allow only non-build host plumbing; record every Cargo/profile setting here."""
    require(target in TARGETS, f"unsupported binary target: {target}")
    source = os.environ if inherited is None else inherited
    allowed = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR",
               "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
               "SSL_CERT_FILE", "SSL_CERT_DIR", "RUSTUP_HOME", "MISE_DATA_DIR")
    env = {key: source[key] for key in allowed if key in source}
    env.update({
        "CARGO_HOME": str(root / "cargo-home"),
        "CARGO_TARGET_DIR": str(root / "target"),
        "CARGO_BUILD_BUILD_DIR": str(root / "build"),
        "CARGO_BUILD_JOBS": "4",
        "CARGO_INCREMENTAL": "0",
        "CARGO_PROFILE_RELEASE_LTO": "thin",
        "CARGO_PROFILE_RELEASE_STRIP": "symbols",
        "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "1",
        "CARGO_PROFILE_RELEASE_PANIC": "unwind",
    })
    return env


def target_command(toolchain: str, target: str, manifest: Path,
                   name: str, kind: str, config: list[str] | None = None) -> list[str]:
    require(toolchain == TOOLCHAIN, f"release compiler must be Rust {TOOLCHAIN}")
    require(target in TARGETS, f"unsupported binary target: {target}")
    require(kind in ("bin", "lib", "example"), "invalid release target kind")
    prefix = ["cargo", f"+{toolchain}"]
    if target == TARGETS[1]:
        prefix.append("xwin")
    return [*prefix, "build", *(config or []), "--manifest-path", str(manifest), "--release", "--locked",
            "--target", target, f"--{kind}", *([] if kind == "lib" else [name])]


def validate_build_graph(metadata: dict, unpack: Path, root_name: str,
                         version: str, mode: str, runtime_features: dict[str, set[str]]) -> dict:
    result = validate_metadata(metadata, unpack, root_name, version, mode, runtime_features)
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    roots = [package["id"] for package in packages.values() if package["name"] == root_name]
    require(len(roots) == 1, f"{root_name} metadata root is ambiguous")
    pending, reachable = roots[:], set()
    while pending:
        item = pending.pop()
        if item in reachable:
            continue
        reachable.add(item)
        for dep in nodes[item].get("deps", []):
            if any(kind.get("kind") in (None, "build") for kind in dep.get("dep_kinds", [])):
                pending.append(dep["pkg"])
    resolved_sources = []
    for item in reachable:
        package = packages[item]
        if package["name"] not in INTERNAL:
            require(package.get("source") == REGISTRY_SOURCE,
                    f"{package['name']} resolved from a non-registry source")
        source = package.get("source")
        if package["name"] == root_name:
            source = "verified-unpacked-root"
        elif package["name"] in INTERNAL and mode == "archive":
            source = "verified-archive-patch"
        resolved_sources.append({"name": package["name"], "version": package["version"],
                                 "source": source})
    require(not runtime_features.get(root_name),
            f"{root_name} enables unexpected release features: {sorted(runtime_features.get(root_name, set()))}")
    for name in INTERNAL:
        require("native-owner-test-hooks" not in runtime_features.get(name, set()),
                f"{name} enables native owner test hooks")
    return {**result, "resolved_sources": sorted(resolved_sources,
            key=lambda item: (item["name"], item["version"], item["source"]))}


def _run(command: list[str], cwd: Path, env: dict) -> str:
    result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True)
    require(result.returncode == 0,
            f"{' '.join(command)} failed in {cwd}: {(result.stderr or result.stdout)[-4000:]}")
    return result.stdout


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _unpack_registry(inventory: dict, registry: Registry, package_dir: Path,
                     unpack: Path) -> dict[str, Path]:
    unpack.mkdir()
    roots = {}
    for record in inventory["packages"]:
        name, version = record["name"], record["version"]
        raw = registry.download(name, version, record["sha256"])
        archive = package_dir / record["archive"]
        archive.write_bytes(raw)
        entries = archive_entries(archive, name, version)
        require(sorted(entries) == record["files"], f"{name} registry archive file inventory differs")
        root = unpack / f"{name}-{version}"
        root.mkdir()
        for relative, data in entries.items():
            target = root.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(data)
        roots[name] = root
    return roots


def _tool_versions(repo: Path, env: dict, toolchain: str, target: str) -> dict:
    versions = {
        "rustc": _run(["rustc", f"+{toolchain}", "--version"], repo, env).strip(),
        "cargo": _run(["cargo", f"+{toolchain}", "--version"], repo, env).strip(),
        "protoc": _run(["protoc", "--version"], repo, env).strip(),
    }
    require(versions["rustc"].startswith(f"rustc {toolchain} "), "release rustc version differs")
    require(versions["cargo"].startswith(f"cargo {toolchain} "), "release Cargo version differs")
    if target == TARGETS[1]:
        versions["cargo_xwin"] = _run(["cargo", "xwin", "--version"], repo, env).strip()
        require(versions["cargo_xwin"] == XWIN_VERSION, "release cargo-xwin version differs")
    return versions


def _runtime_features(root: Path, env: dict, toolchain: str, target: str,
                      config: list[str], name: str) -> dict[str, set[str]]:
    output = _run(["cargo", f"+{toolchain}", *config, "tree", "--manifest-path",
                   str(root / "Cargo.toml"), "--locked", "--target", target,
                   "-p", name, "-e", "normal,build", "--prefix", "none", "-f", "{p}|{f}"], root, env)
    features: dict[str, set[str]] = {}
    for line in output.splitlines():
        package, marker, enabled = line.partition("|")
        require(marker == "|" and " v" in package, f"invalid Cargo runtime tree line: {line}")
        package_name = package.split(" v", 1)[0]
        features.setdefault(package_name, set()).update(
            enabled.removesuffix(" (*)").split(",") if enabled else ())
    require(name in features, f"runtime feature tree misses {name}")
    return features


def _metadata(root: Path, env: dict, toolchain: str, target: str,
              config: list[str]) -> dict:
    output = _run(["cargo", f"+{toolchain}", *config, "metadata", "--manifest-path",
                   str(root / "Cargo.toml"), "--format-version", "1", "--locked",
                   "--filter-platform", target], root, env)
    try:
        return json.loads(output)
    except ValueError as exc:
        raise ReleaseError(f"invalid Cargo metadata: {exc}") from exc


def _locked_names(path: Path) -> set[str]:
    lock = tomllib.loads(path.read_text(encoding="utf-8"))
    return {item["name"] for item in lock["package"] if item["name"] in INTERNAL}


def _artifact_name(name: str, target: str) -> str:
    if name == "pkcs11-proxy-ng-shim":
        return "pkcs11_proxy_ng_shim.dll" if target == TARGETS[1] else "libpkcs11_proxy_ng_shim.so"
    return name + (".exe" if target == TARGETS[1] else "")


def _git_tag(repo: Path, commit: str, version: str) -> dict | None:
    tag = f"v{version}"
    result = subprocess.run(["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{tag}}"],
                            cwd=repo, text=True, capture_output=True)
    if result.returncode != 0:
        return None
    object_id = result.stdout.strip()
    peeled = subprocess.run(["git", "rev-parse", f"refs/tags/{tag}^{{commit}}"],
                            cwd=repo, text=True, capture_output=True)
    if peeled.returncode != 0 or peeled.stdout.strip() != commit:
        return None
    return {"name": tag, "object_sha": object_id}


def build_binaries(repo: Path, inventory_path: Path, package_dir: Path, source: str,
                   target: str, output: Path, toolchain: str = TOOLCHAIN,
                   *, registry: Registry | None = None) -> dict:
    """Build all entry points in isolated roots and retain notice inputs."""
    repo, inventory_path, package_dir, output = map(Path, (repo, inventory_path, package_dir, output))
    require(source in ("archive", "registry"), "binary source must be archive or registry")
    require(target in TARGETS, f"unsupported binary target: {target}")
    require(toolchain == TOOLCHAIN, f"release compiler must be Rust {TOOLCHAIN}")
    validate_release_profile(repo)
    require(not output.exists() and not output.is_symlink(), f"binary output already exists: {output}")
    require(all(not path.is_symlink() for path in (output, *output.parents)),
            f"binary output path follows a symlink: {output}")
    require(not output.resolve().is_relative_to(repo.resolve()), "binary output must be outside source checkout")
    inventory = read_inventory(inventory_path)
    observed = inspect_archives(repo, package_dir)
    require(inventory == observed, "candidate inventory differs from clean source archives")
    output.mkdir(parents=True, exist_ok=False)
    unpack = output / "unpacked"
    if source == "archive":
        roots = extract_verified_archives(repo, package_dir, unpack)
        archive_paths = {item["name"]: package_dir / item["archive"]
                         for item in inventory["packages"]}
    else:
        registry = registry or Registry()
        verified = verify_publication(inventory, registry)
        require(verified["state"] == "complete", "all eight registry packages must be verified")
        downloads = output / "verified-archives"
        downloads.mkdir()
        roots = _unpack_registry(inventory, registry, downloads, unpack)
        archive_paths = {item["name"]: downloads / item["archive"] for item in inventory["packages"]}
    hashes = {item["name"]: item["sha256"] for item in inventory["packages"]}
    external = _external_lock(repo)
    original_locks = output / "original-locks"
    original_locks.mkdir()
    for name, root in roots.items():
        lock_path = root / "Cargo.lock"
        require(lock_path.is_file(), f"{name} packaged Cargo.lock is absent")
        required = _locked_names(lock_path)
        require(name in required, f"{name} packaged Cargo.lock misses its root")
        reconcile_lock(tomllib.loads(lock_path.read_text(encoding="utf-8")), external,
                       inventory["version"], required, hashes)
        shutil.copy2(lock_path, original_locks / f"{name}.lock")
    session = output / "session"
    session.mkdir()
    env = release_environment(session, target)
    Path(env["CARGO_HOME"]).mkdir()
    versions = _tool_versions(repo, env, toolchain, target)
    rust_sysroot = _run(["rustc", f"+{toolchain}", "--print", "sysroot"], repo, env).strip()
    require(Path(rust_sysroot).is_absolute(), "release rustc returned a non-absolute sysroot")
    graphs = {}
    binaries = output / "binaries"
    binaries.mkdir()
    artifacts = []
    for name in ROOTS:
        root = roots[name]
        root_env = env
        original_path = original_locks / f"{name}.lock"
        expected_lock = original_path.read_bytes()
        locked = _locked_names(original_path)
        config = [] if source == "registry" else _patches(roots, name, locked)
        if source == "archive":
            _seed_lock(original_path, root / "Cargo.lock", external, inventory["version"], hashes, locked)
        graph = _metadata(root, root_env, toolchain, target, config)
        features = _runtime_features(root, root_env, toolchain, target, config, name)
        checked = validate_build_graph(graph, unpack, name, inventory["version"], source, features)
        if source == "registry":
            require((root / "Cargo.lock").read_bytes() == expected_lock,
                    f"{name} packaged registry lock changed during graph resolution")
        graphs[name] = {"metadata": graph, "runtime_features": {k: sorted(v) for k, v in features.items()},
                        "checked": checked, "config": config, "lock_path": str(root / "Cargo.lock"),
                        "original_lock_path": str(original_path), "source_root": str(root)}
        targets = [("lib", name)] if name == "pkcs11-proxy-ng-shim" else [("bin", name)]
        if target == TARGETS[1] and name == "pkcs11-proxy-ng-shim":
            require((root / "examples/cross_width_smoke.rs").is_file(),
                    "published shim archive lacks cross_width_smoke example")
            targets.append(("example", "cross_width_smoke"))
        for kind, build_name in targets:
            command = target_command(toolchain, target, root / "Cargo.toml", build_name, kind, config)
            print(f"binary-build: {source} {target} {name} {kind}", file=sys.stderr, flush=True)
            _run(command, root, root_env)
            if source == "registry":
                require((root / "Cargo.lock").read_bytes() == expected_lock,
                        f"{name} packaged registry lock changed during build")
            basename = _artifact_name(build_name, target)
            built = Path(root_env["CARGO_TARGET_DIR"]) / target / "release"
            if kind == "example":
                built /= "examples"
            built /= basename
            require(built.is_file(), f"release artifact missing at {built}")
            staged = binaries / basename
            require(not staged.exists(), f"duplicate release artifact: {basename}")
            shutil.copy2(built, staged)
            if target == TARGETS[0] and kind == "bin":
                validate_version_line(_run([str(staged), "--version"], repo, root_env),
                                      name, inventory["version"])
            if target == TARGETS[0] and kind == "lib":
                require(set(_shim_exports(staged)) == {"C_GetFunctionList", "C_GetInterfaceList", "C_GetInterface"},
                        "Linux shim exports differ")
            artifacts.append({"name": basename, "sha256": _sha256(staged), "size": staged.stat().st_size,
                              "package": name, "kind": kind})
    local = {"format_version": 1, "source_mode": source, "target": target,
             "inventory_path": str(inventory_path.resolve()), "package_dir": str(package_dir.resolve()),
             "cargo_home": env["CARGO_HOME"], "rust_sysroot": rust_sysroot,
             "archive_paths": {k: str(v.resolve()) for k, v in archive_paths.items()},
             "source_roots": {k: str(v.resolve()) for k, v in roots.items()},
             "graphs": graphs, "binaries": {item["name"]: str((binaries / item["name"]).resolve())
                                           for item in artifacts}}
    (output / "build-inputs.json").write_text(json.dumps(local, indent=2, sort_keys=True) + "\n")
    portable = {"format_version": 1, "source_mode": source,
                "github_publication_eligible": source == "registry",
                "version": inventory["version"], "source_commit": inventory["source_commit"],
                "source_tag": _git_tag(repo, inventory["source_commit"], inventory["version"]),
                "target": target, "tools": versions,
                "profile": {"name": "release", "lto": "thin", "strip": "symbols",
                            "codegen_units": 1, "panic": "unwind", "incremental": False, "jobs": 4},
                "flags": {"rustflags": [], "rustdocflags": []},
                "inventory_sha256": _sha256(inventory_path),
                "archives": {item["name"]: item["sha256"] for item in inventory["packages"]},
                "original_locks": {name: _sha256(original_locks / f"{name}.lock") for name in roots},
                "effective_locks": {name: _sha256(roots[name] / "Cargo.lock") for name in ROOTS},
                "graphs": {name: {"packages": data["checked"]["packages"],
                                  "runtime_features": data["runtime_features"],
                                  "resolved_sources": data["checked"]["resolved_sources"]}
                           for name, data in graphs.items()},
                "artifacts": artifacts}
    (output / "build-provenance.json").write_text(json.dumps(portable, indent=2, sort_keys=True) + "\n")
    return portable

"""Build release binaries from checksum-bound published or candidate crate sources."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import shutil
import subprocess
import tomllib

from .package_archives import archive_entries, extract_verified_archives, inspect_archives
from .package_consumers import (_external_lock, _patches, _seed_lock, reconcile_lock,
                                validate_metadata, validate_version_line, REGISTRY_SOURCE, _shim_exports)
from .package_model import INTERNAL, ReleaseError, require
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


def require_registry_provenance(path: Path) -> dict:
    try:
        provenance = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise ReleaseError(f"cannot read binary provenance {path}: {exc}") from exc
    require(isinstance(provenance, dict) and provenance.get("format_version") == 1 and
            provenance.get("source_mode") == "registry" and
            provenance.get("github_publication_eligible") is True,
            "GitHub publication requires registry-source binary provenance")
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
    for item in reachable:
        package = packages[item]
        if package["name"] not in INTERNAL:
            require(package.get("source") == REGISTRY_SOURCE,
                    f"{package['name']} resolved from a non-registry source")
    require(not runtime_features.get(root_name),
            f"{root_name} enables unexpected release features: {sorted(runtime_features.get(root_name, set()))}")
    for name in INTERNAL:
        require("native-owner-test-hooks" not in runtime_features.get(name, set()),
                f"{name} enables native owner test hooks")
    return result


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
                "graphs": {name: {"packages": data["checked"]["packages"],
                                  "runtime_features": data["runtime_features"]}
                           for name, data in graphs.items()},
                "artifacts": artifacts}
    (output / "build-provenance.json").write_text(json.dumps(portable, indent=2, sort_keys=True) + "\n")
    return portable

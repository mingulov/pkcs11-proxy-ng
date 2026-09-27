"""Compile and inspect independent consumers of verified package sources."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib

from .package_archives import extract_verified_archives, inspect_archives
from .package_model import INTERNAL, PACKAGES, require
from .package_registry import Registry, read_inventory, verify_publication


REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
THIN = {"pkcs11-proxy-ng-client", "pkcs11-proxy-ng-shim", "pkcs11-proxy-ng-cli"}
FORBIDDEN_PACKAGES = {"pkcs11-proxy-ng", "pkcs11-proxy-ng-backend"}
FORBIDDEN_FEATURES = {
    "tonic": {"server", "router", "transport"},
    "tokio": {"signal", "process"},
    "hyper": {"server", "server-auto", "server-graceful"},
    "hyper-util": {"server", "server-auto", "server-graceful"},
}


def reconcile_lock(lock: dict, external: set[tuple], version: str,
                   required_internal: set[str], hashes: dict[str, str] | None = None) -> None:
    packages = lock.get("package")
    require(isinstance(packages, list), "packaged Cargo.lock lacks package records")
    seen = set()
    present = set()
    for item in packages:
        require(isinstance(item, dict), "packaged Cargo.lock has invalid record")
        name, locked_version, source = item.get("name"), item.get("version"), item.get("source")
        identity = (name, locked_version, source)
        require(identity not in seen, f"duplicate locked package {name}")
        seen.add(identity)
        if name in INTERNAL:
            require(locked_version == version, f"{name} locked at wrong version")
            require(source in (None, REGISTRY_SOURCE), f"{name} has wrong locked source")
            if source is not None and hashes is not None:
                require(item.get("checksum") == hashes[name], f"{name} locked checksum differs")
            present.add(name)
        else:
            require((name, locked_version, source, item.get("checksum")) in external,
                    f"{name} external locked identity differs from committed workspace lock")
    require(required_internal <= present,
            f"packaged Cargo.lock misses internal packages: {sorted(required_internal - present)}")


def _normal_ids(metadata: dict, root_name: str) -> tuple[dict, dict, set[str]]:
    packages = {package["id"]: package for package in metadata.get("packages", [])}
    nodes = {node["id"]: node for node in metadata.get("resolve", {}).get("nodes", [])}
    roots = [item["id"] for item in packages.values() if item["name"] == root_name]
    require(len(roots) == 1, f"{root_name} missing or ambiguous in Cargo metadata")
    pending = roots[:]
    reachable = set()
    while pending:
        item = pending.pop()
        if item in reachable:
            continue
        require(item in packages and item in nodes, f"metadata graph misses {item}")
        reachable.add(item)
        for dep in nodes[item].get("deps", []):
            if any(kind.get("kind") in (None, "build") for kind in dep.get("dep_kinds", [])):
                pending.append(dep["pkg"])
    return packages, nodes, reachable


def validate_metadata(metadata: dict, unpack: Path, root_name: str,
                      version: str, mode: str) -> dict:
    """Reject source leaks and thin-root server features in Cargo's resolved graph."""
    require(mode in ("archive", "registry"), "unknown consumer source mode")
    packages, nodes, reachable = _normal_ids(metadata, root_name)
    unpack = Path(unpack).resolve()
    roots = {name: unpack / f"{name}-{version}" for name, _ in PACKAGES}
    observed = set()
    for item in reachable:
        package = packages[item]
        name = package["name"]
        if name in INTERNAL:
            require(package["version"] == version, f"{name} resolved wrong version")
            observed.add(name)
            source = package.get("source")
            path = Path(package["manifest_path"]).resolve()
            if mode == "archive":
                require(source is None and path == roots[name] / "Cargo.toml",
                        f"{name} resolved outside verified archive roots: {path}")
            elif name == root_name and path == roots[name] / "Cargo.toml":
                require(source is None, f"{name} unpacked registry root has unexpected source")
            else:
                require(source == REGISTRY_SOURCE, f"{name} resolved from local source")
        if root_name in THIN:
            require(name not in FORBIDDEN_PACKAGES, f"{root_name} includes server package {name}")
            forbidden = FORBIDDEN_FEATURES.get(name, set())
            active = set(nodes[item].get("features", []))
            require(not (active & forbidden),
                    f"{root_name} enables server-only {name} features {sorted(active & forbidden)}")
    require(root_name in observed, f"{root_name} not in resolved graph")
    return {"packages": sorted(observed), "graph_packages": len(reachable)}


def _run(command: list[str], cwd: Path, env: dict, *, capture=True) -> str:
    result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=capture)
    require(result.returncode == 0,
            f"{' '.join(command)} failed in {cwd}: {(result.stderr or result.stdout)[-4000:]}")
    return result.stdout


def _cargo(toolchain: str, *args: str) -> list[str]:
    return ["cargo", f"+{toolchain}", *args]


def _environment(root: Path, cargo_home: Path) -> dict:
    env = os.environ.copy()
    cargo_home.mkdir(exist_ok=True)
    env["CARGO_HOME"] = str(cargo_home)
    env["CARGO_TARGET_DIR"] = str(root / "target")
    env["CARGO_BUILD_BUILD_DIR"] = str(root / "build")
    env["CARGO_INCREMENTAL"] = "0"
    env["CARGO_BUILD_JOBS"] = "4"
    env["RUSTFLAGS"] = "-C debuginfo=0"
    env["RUSTDOCFLAGS"] = "-C debuginfo=0"
    return env


def _metadata(cwd: Path, env: dict, toolchain: str, config: list[str]) -> dict:
    output = _run(_cargo(toolchain, *config, "metadata", "--format-version", "1", "--locked"), cwd, env)
    return json.loads(output)


def _patches(roots: dict[str, Path], root_name: str) -> list[str]:
    return [arg for name, path in roots.items() if name != root_name
            for arg in ("--config", f'patch.crates-io.{name}.path="{path}"')]


def _seed_lock(lock_path: Path, output: Path, external: set[tuple],
               version: str, hashes: dict[str, str], expected: set[str]) -> None:
    original = lock_path.read_text(encoding="utf-8")
    lock = tomllib.loads(original)
    reconcile_lock(lock, external, version, expected, hashes)
    # Cargo's archive lock records internal registry checksums; a local patch
    # changes only those internal identities to path packages. External bytes
    # remain exactly the packaged lock entries and are rechecked afterward.
    chunks = re.split(r"(?=^\[\[package\]\]$)", original, flags=re.MULTILINE)
    seeded = []
    for chunk in chunks:
        match = re.search(r'^name = "([^"]+)"$', chunk, flags=re.MULTILINE)
        if match and match.group(1) in INTERNAL:
            chunk = re.sub(r'^source = "[^"]+"\n', "", chunk, flags=re.MULTILINE)
            chunk = re.sub(r'^checksum = "[^"]+"\n', "", chunk, flags=re.MULTILINE)
        seeded.append(chunk)
    output.write_text("".join(seeded), encoding="utf-8")
    reconcile_lock(tomllib.loads(output.read_text(encoding="utf-8")), external, version, expected)


def _external_lock(repo: Path) -> set[tuple]:
    lock = tomllib.loads((repo / "Cargo.lock").read_text(encoding="utf-8"))
    return {(item["name"], item["version"], item.get("source"), item.get("checksum"))
            for item in lock["package"] if item.get("source") is not None}


def _root_check(name: str, roots: dict[str, Path], base: Path, env: dict,
                toolchain: str, external: set[tuple], version: str, hashes: dict[str, str],
                *, registry=False) -> dict:
    root = roots[name]
    config = [] if registry else _patches(roots, name)
    if not registry:
        expected = {item for item in INTERNAL if item in
                    {package["name"] for package in tomllib.loads((root / "Cargo.lock").read_text())["package"]}}
        _seed_lock(root / "Cargo.lock", root / "Cargo.lock", external, version, hashes, expected)
    graph = _metadata(root, env, toolchain, config)
    result = validate_metadata(graph, base, name, version, "registry" if registry else "archive")
    if registry:
        require((root / "Cargo.lock").read_bytes() == (base / "original-locks" / f"{name}.lock").read_bytes(),
                f"{name} packaged registry lock changed")
    return {"config": config, **result}


def _shim_exports(library: Path) -> list[str]:
    command = ["python3", "-c",
               "import ctypes,sys; lib=ctypes.CDLL(sys.argv[1]); "
               "[getattr(lib,n) for n in ('C_GetFunctionList','C_GetInterfaceList','C_GetInterface')]; "
               "print('C_GetFunctionList C_GetInterfaceList C_GetInterface')", str(library)]
    result = subprocess.run(command, text=True, capture_output=True)
    require(result.returncode == 0, f"shim export loader failed: {result.stderr}")
    return result.stdout.split()


def _consume(roots: dict[str, Path], base: Path, repo: Path, toolchain: str,
             version: str, hashes: dict[str, str], *, registry=False) -> dict:
    external = _external_lock(repo)
    results = {}
    for name in ("pkcs11-proxy-ng-client", "pkcs11-proxy-ng-shim",
                 "pkcs11-proxy-ng", "pkcs11-proxy-ng-cli", "pkcs11-proxy-ng-proto"):
        session = base / ("root-" + name)
        session.mkdir()
        env = _environment(session, base / "cargo-home")
        if registry:
            (base / "original-locks").mkdir(exist_ok=True)
            shutil.copy2(roots[name] / "Cargo.lock", base / "original-locks" / f"{name}.lock")
        graph = _root_check(name, roots, base, env, toolchain, external,
                            version, hashes, registry=registry)
        config = graph.pop("config")
        root = roots[name]
        if name in ("pkcs11-proxy-ng", "pkcs11-proxy-ng-cli"):
            install = base / ("install-" + name)
            _run(_cargo(toolchain, *config, "install", "--path", str(root),
                        "--root", str(install), "--locked", "--force"), root, env)
            output = _run([str(install / "bin" / name), "--version"], root, env).strip()
            require(output.split()[-1] == version, f"{name} installed version differs: {output}")
            graph["installed_version"] = output
        elif name == "pkcs11-proxy-ng-shim":
            _run(_cargo(toolchain, *config, "build", "--release", "--lib", "--locked"), root, env)
            library = session / "target" / "release" / "libpkcs11_proxy_ng_shim.so"
            require(library.is_file(), f"shim library missing at {library}")
            graph["exports"] = _shim_exports(library)
        elif name == "pkcs11-proxy-ng-client":
            _run(_cargo(toolchain, *config, "check", "--example", "remote_client", "--locked"), root, env)
            graph["example"] = "remote_client checked"
        elif name == "pkcs11-proxy-ng-proto":
            _run(_cargo(toolchain, *config, "doc", "--lib", "--no-deps", "--locked"), root, env)
            graph["docs"] = "proto library docs generated"
        results[name] = graph
    return results


def archive_consumer(repo: Path, package_dir: Path, toolchain: str) -> dict:
    inventory = inspect_archives(repo, package_dir)
    with tempfile.TemporaryDirectory(prefix="pkcs11-archive-consumer-") as temp:
        base = Path(temp)
        roots = extract_verified_archives(repo, package_dir, base / "unpacked")
        hashes = {item["name"]: item["sha256"] for item in inventory["packages"]}
        return _consume(roots, base, repo, toolchain, inventory["version"], hashes)


def registry_consumer(repo: Path, inventory_path: Path, toolchain: str,
                      registry: Registry | None = None) -> dict:
    inventory = read_inventory(inventory_path)
    registry = registry or Registry()
    result = verify_publication(inventory, registry)
    require(result["state"] == "complete", "all eight registry packages must be verified")
    with tempfile.TemporaryDirectory(prefix="pkcs11-registry-consumer-") as temp:
        base = Path(temp)
        unpack = base / "unpacked"
        unpack.mkdir()
        from .package_archives import archive_entries
        roots = {}
        for item in inventory["packages"]:
            name, version = item["name"], inventory["version"]
            content = registry.download(name, version, item["sha256"])
            archive = base / item["archive"]
            archive.write_bytes(content)
            entries = archive_entries(archive, name, version)
            root = unpack / f"{name}-{version}"
            root.mkdir()
            for relative, data in entries.items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            roots[name] = root
        hashes = {item["name"]: item["sha256"] for item in inventory["packages"]}
        return _consume(roots, base, repo, toolchain, inventory["version"], hashes, registry=True)

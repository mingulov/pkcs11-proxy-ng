"""Source manifest contract for the eight public proxy packages."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import tomllib


class ReleaseError(Exception):
    """A release package violates the source or archive contract."""


PACKAGES = (
    ("pkcs11-proxy-ng-types", "types"),
    ("pkcs11-proxy-ng-audit", "audit"),
    ("pkcs11-proxy-ng-proto", "proto"),
    ("pkcs11-proxy-ng-client", "client"),
    ("pkcs11-proxy-ng-backend", "backend"),
    ("pkcs11-proxy-ng", "server"),
    ("pkcs11-proxy-ng-shim", "shim"),
    ("pkcs11-proxy-ng-cli", "cli"),
)
INTERNAL = {name for name, _ in PACKAGES}
EDGES = {
    "types": set(), "audit": set(),
    "proto": {"pkcs11-proxy-ng-types"},
    "client": {"pkcs11-proxy-ng-types", "pkcs11-proxy-ng-proto"},
    "backend": {"pkcs11-proxy-ng-types", "pkcs11-proxy-ng-proto"},
    "server": {"pkcs11-proxy-ng-types", "pkcs11-proxy-ng-proto",
               "pkcs11-proxy-ng-backend", "pkcs11-proxy-ng-audit"},
    "shim": {"pkcs11-proxy-ng-types", "pkcs11-proxy-ng-client", "pkcs11-proxy-ng-proto"},
    "cli": {"pkcs11-proxy-ng-types", "pkcs11-proxy-ng-client", "pkcs11-proxy-ng-audit"},
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseError(message)


def read_toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseError(f"cannot read {path}: {exc}") from exc


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True)
    require(result.returncode == 0, f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def source_sections(manifest: dict):
    for kind in ("dependencies", "build-dependencies", "dev-dependencies"):
        yield kind, manifest.get(kind, {})
    for target, details in manifest.get("target", {}).items():
        for kind in ("dependencies", "build-dependencies", "dev-dependencies"):
            yield f"target.{target}.{kind}", details.get(kind, {})


def effective_dep(spec: object, workspace: dict, name: str) -> dict:
    if isinstance(spec, str):
        return {"version": spec}
    require(isinstance(spec, dict), f"{name} dependency specification invalid")
    if spec.get("workspace") is True:
        inherited = workspace.get("workspace", {}).get("dependencies", {}).get(name)
        require(inherited is not None, f"missing workspace dependency {name}")
        base = {"version": inherited} if isinstance(inherited, str) else dict(inherited)
        require(isinstance(base, dict), f"invalid workspace dependency {name}")
        merged = {**base, **{k: v for k, v in spec.items() if k not in ("workspace", "features")}}
        if "features" in base or "features" in spec:
            merged["features"] = list(base.get("features", [])) + list(spec.get("features", []))
        return merged
    return dict(spec)


def checked_workspace(repo: Path) -> str:
    workspace = read_toml(repo / "Cargo.toml")
    section = workspace.get("workspace", {})
    version = section.get("package", {}).get("version")
    require(isinstance(version, str) and bool(re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?", version)),
            "invalid workspace version")
    expected_members = {f"crates/{directory}" for _, directory in PACKAGES}
    require(set(section.get("members", [])) == expected_members and
            len(section.get("members", [])) == len(PACKAGES),
            "workspace package set differs from eight release crates")
    require({path.parent.relative_to(repo).as_posix() for path in (repo / "crates").glob("*/Cargo.toml")}
            == expected_members, "crate manifest set differs from eight release crates")
    for name, directory in PACKAGES:
        manifest = read_toml(repo / "crates" / directory / "Cargo.toml")
        package = manifest.get("package", {})
        require(package.get("name") == name, f"{directory} has wrong package name")
        source_version = package.get("version")
        actual_version = version if source_version == {"workspace": True} else source_version
        require(actual_version == version, f"{name} version differs from workspace")
        require(package.get("publish") == ["crates-io"], f"{name} registry differs from crates-io")
        required = {"Cargo.toml", "README.md", "LICENSE-APACHE", "LICENSE-MIT", "src/**"}
        require(required <= set(package.get("include", [])), f"{name} omits package source inputs")
        normal = set()
        for label, deps in source_sections(manifest):
            require(isinstance(deps, dict), f"invalid {name} {label}")
            for dependency, raw in deps.items():
                spec = effective_dep(raw, workspace, dependency)
                require("git" not in spec and "branch" not in spec and "rev" not in spec and "tag" not in spec,
                        f"{name} uses a git source for {dependency}")
                is_dev = label.endswith("dev-dependencies")
                if dependency in INTERNAL:
                    require("path" in spec, f"{name} {dependency} must use local source path")
                    expected_dir = dict(PACKAGES)[dependency]
                    require((repo / "crates" / directory / spec["path"]).resolve() ==
                            (repo / "crates" / expected_dir).resolve(),
                            f"{name} {dependency} points outside intended crate")
                    if is_dev:
                        require("version" not in spec, f"{name} {dependency} dev dependency must be path-only")
                    else:
                        require(spec.get("version") == f"={version}",
                                f"{name} {dependency} has wrong exact version")
                        if label == "dependencies":
                            normal.add(dependency)
                        elif label.endswith("build-dependencies"):
                            raise ReleaseError(f"{name} has unexpected internal build dependency {dependency}")
                else:
                    require("path" not in spec and isinstance(spec.get("version"), str),
                            f"{name} external dependency {dependency} needs a registry version")
        require(normal == EDGES[directory], f"{name} has wrong internal dependency graph")
    return version

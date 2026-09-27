"""Controlled registry publication and recovery cases."""

from pathlib import Path
import hashlib
import io
import json
import sys
import subprocess
import tarfile
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from release.package_model import EDGES, PACKAGES, ReleaseError  # noqa: E402
from release.package_registry import Registry, publication_state, read_inventory, verify_publication  # noqa: E402
from release.package_consumers import REGISTRY_SOURCE, registry_consumer  # noqa: E402
import release_checks  # noqa: E402


class FakeTransport:
    def __init__(self, replies):
        self.replies = replies

    def __call__(self, url):
        value = self.replies.get(url, (404, b""))
        if isinstance(value, Exception):
            raise value
        if isinstance(value, list):
            return value.pop(0) if len(value) > 1 else value[0]
        return value


class ControlledCargo:
    """Cargo process boundary for a local, checksum-bound registry fixture."""

    def __init__(self, inventory, locks, *, local_dependency=False,
                 mutate_lock=False, wrong_client_version=False):
        self.inventory = inventory
        self.locks = locks
        self.local_dependency = local_dependency
        self.mutate_lock = mutate_lock
        self.wrong_client_version = wrong_client_version
        self.commands = []
        self.docs = []
        self.installs = []
        self.checks = []
        self.shim_built = False
        self.exports_loaded = False

    @staticmethod
    def _closure(name):
        names = {name}
        pending = [name]
        by_name = dict(PACKAGES)
        while pending:
            current = pending.pop()
            for dep in EDGES[by_name[current]]:
                if dep not in names:
                    names.add(dep)
                    pending.append(dep)
        return names

    def _metadata(self, root, cwd, env):
        example = cwd.name == "example-client"
        if example:
            manifest = tomllib.loads((cwd / "Cargo.toml").read_text())
            project = {name for name in manifest["dependencies"] if name.startswith("pkcs11-proxy-ng")}
            assert project == {"pkcs11-proxy-ng-client"}
            assert manifest["dependencies"]["pkcs11-proxy-ng-client"] == {"version": "=0.2.0"}
            assert manifest["dependencies"]["tokio"]["features"] == ["macros", "rt"]
        else:
            assert (cwd / "Cargo.lock").read_bytes() == self.locks[root], root
            if self.mutate_lock and root == "pkcs11-proxy-ng-client":
                (cwd / "Cargo.lock").write_bytes(self.locks[root] + b"\n")
                self.mutate_lock = False
        names = self._closure(root)
        packages = []
        nodes = []
        ids = {name: f"registry+{name}#0.2.0" for name in names}
        if not example:
            ids[root] = f"path+{root}#0.2.0"
        for name in sorted(names):
            source = REGISTRY_SOURCE if example or name != root else None
            path = (cwd / "Cargo.toml" if name == root and not example else
                    Path(env["CARGO_HOME"]) / "registry/src/local" / f"{name}-0.2.0/Cargo.toml")
            if self.local_dependency and name == "pkcs11-proxy-ng-proto" and root == "pkcs11-proxy-ng-client":
                source = None
                path = ROOT / "crates/proto/Cargo.toml"
            version = "0.3.0" if self.wrong_client_version and example and name == root else "0.2.0"
            packages.append({"id": ids[name], "name": name, "version": version,
                             "source": source, "manifest_path": str(path)})
            deps = [{"pkg": ids[dep], "dep_kinds": [{"kind": None}]}
                    for dep in EDGES[dict(PACKAGES)[name]] if dep in names]
            nodes.append({"id": ids[name], "features": [], "deps": deps})
        return json.dumps({"packages": packages, "resolve": {"nodes": nodes}})

    def __call__(self, command, *, cwd=None, env=None, **_kwargs):
        cwd = Path(cwd) if cwd is not None else None
        if command[0] == "python3":
            assert Path(command[-1]).is_file()
            self.exports_loaded = True
            return subprocess.CompletedProcess(command, 0,
                                               "C_GetFunctionList C_GetInterfaceList C_GetInterface\n", "")
        if command[0] != "cargo":
            assert command[-1] == "--version"
            return subprocess.CompletedProcess(command, 0, f"{Path(command[0]).name} 0.2.0\n", "")
        assert command[1] == "+1.88.0"
        assert "--config" not in command, "registry Cargo command included a path patch"
        assert env["CARGO_TARGET_DIR"] != env["CARGO_BUILD_BUILD_DIR"]
        self.commands.append((command, cwd))
        root = "pkcs11-proxy-ng-client" if cwd.name == "example-client" else cwd.name.removesuffix("-0.2.0")
        action = next(arg for arg in command if arg in
                      ("metadata", "tree", "install", "build", "check", "doc"))
        if not (action == "metadata" and cwd.name == "example-client" and "--locked" not in command):
            assert "--locked" in command, f"unlocked registry command: {command}"
        if action == "metadata":
            return subprocess.CompletedProcess(command, 0, self._metadata(root, cwd, env), "")
        if action == "tree":
            lines = [f"{name} v0.2.0|" for name in sorted(self._closure(root))]
            return subprocess.CompletedProcess(command, 0, "\n".join(lines) + "\n", "")
        if action == "install":
            install_root = Path(command[command.index("--root") + 1])
            bin_path = install_root / "bin" / root
            bin_path.parent.mkdir(parents=True)
            bin_path.write_bytes(b"controlled fixture\n")
            self.installs.append(root)
        elif action == "build":
            assert root == "pkcs11-proxy-ng-shim" and "--release" in command and "--lib" in command
            library = Path(env["CARGO_TARGET_DIR"]) / "release/libpkcs11_proxy_ng_shim.so"
            library.parent.mkdir(parents=True, exist_ok=True)
            library.write_bytes(b"controlled fixture\n")
            self.shim_built = True
        elif action == "check":
            self.checks.append((root, cwd.name == "example-client"))
        elif action == "doc":
            assert command[command.index("--target") + 1] == "x86_64-unknown-linux-gnu"
            assert "--lib" in command and "--no-deps" in command
            self.docs.append(root)
        return subprocess.CompletedProcess(command, 0, "", "")


def controlled_registry(root):
    baseline = tomllib.loads((ROOT / "Cargo.lock").read_text())
    tokio = next(item for item in baseline["package"] if item["name"] == "tokio")
    inventory = {"format_version": 1, "source_commit": "a" * 40,
                 "version": "0.2.0", "packages": []}
    replies = {}
    registry = Registry(FakeTransport(replies), pace=False, attempts=2)
    hashes = {}
    locks = {}
    for name, directory in PACKAGES:
        dependencies = sorted(ControlledCargo._closure(name) - {name})
        lock = 'version = 4\n[[package]]\nname = "' + name + '"\nversion = "0.2.0"\n'
        for dep in dependencies:
            lock += ('[[package]]\nname = "' + dep + '"\nversion = "0.2.0"\n'
                     'source = "' + REGISTRY_SOURCE + '"\nchecksum = "' + hashes[dep] + '"\n')
        lock += ('[[package]]\nname = "tokio"\nversion = "' + tokio["version"] + '"\n'
                 'source = "' + tokio["source"] + '"\nchecksum = "' + tokio["checksum"] + '"\n')
        locks[name] = lock.encode()
        content = io.BytesIO()
        with tarfile.open(fileobj=content, mode="w:gz") as archive:
            files = {"Cargo.toml": f'[package]\nname = "{name}"\nversion = "0.2.0"\n'.encode(),
                     "Cargo.lock": locks[name], "src/lib.rs": b"pub fn fixture() {}\n"}
            if directory == "client":
                files["examples/remote_client.rs"] = b"fn main() {}\n"
            for relative, body in files.items():
                info = tarfile.TarInfo(f"{name}-0.2.0/{relative}")
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
        payload = content.getvalue()
        digest = hashlib.sha256(payload).hexdigest()
        hashes[name] = digest
        inventory["packages"].append({"name": name, "version": "0.2.0",
                                      "archive": f"{name}-0.2.0.crate",
                                      "sha256": digest, "files": sorted(files)})
        replies[registry.metadata_url(name, "0.2.0")] = (
            200, json.dumps({"version": {"num": "0.2.0", "checksum": digest,
                                         "yanked": False}}).encode())
        replies[registry.index_url(name)] = (
            200, json.dumps({"name": name, "vers": "0.2.0", "cksum": digest,
                             "yanked": False}).encode() + b"\n")
        replies[registry.download_url(name, "0.2.0")] = (200, payload)
    path = root / "inventory.json"
    path.write_text(json.dumps(inventory))
    return path, registry, locks


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.inventory = {"format_version": 1, "source_commit": "a" * 40,
                          "version": "0.2.0", "packages": [
                              {"name": name, "version": "0.2.0", "archive": f"{name}-0.2.0.crate",
                               "sha256": "b" * 64, "files": ["Cargo.toml"]}
                              for name, _ in PACKAGES]}
        self.replies = {}
        self.registry = Registry(FakeTransport(self.replies), pace=False, attempts=2)

    def publish(self, name, *, checksum=None, yanked=False, api=True, index=True, download=True):
        import json
        digest = checksum or "b" * 64
        if api:
            self.replies[self.registry.metadata_url(name, "0.2.0")] = (
                200, json.dumps({"version": {"num": "0.2.0", "checksum": digest,
                                             "yanked": yanked}}).encode())
        if index:
            self.replies[self.registry.index_url(name)] = (
                200, json.dumps({"name": name, "vers": "0.2.0", "cksum": digest,
                                 "yanked": yanked}).encode() + b"\n")
        if download:
            self.replies[self.registry.download_url(name, "0.2.0")] = (200, b"not a real crate")

    def test_all_missing_and_partial_matching_recovery(self):
        self.assertEqual(publication_state(self.inventory, "workspace", self.registry)["state"], "ready")
        self.publish(PACKAGES[0][0])
        with self.assertRaises(ReleaseError):
            publication_state(self.inventory, "workspace", self.registry)
        self.assertEqual(publication_state(self.inventory, PACKAGES[1][0], self.registry)["state"], "ready")

    def test_selected_published_dependency_missing_and_mismatch_fail(self):
        self.publish(PACKAGES[0][0])
        with self.assertRaises(ReleaseError):
            publication_state(self.inventory, PACKAGES[0][0], self.registry)
        with self.assertRaises(ReleaseError):
            publication_state(self.inventory, "pkcs11-proxy-ng-client", self.registry)
        self.publish(PACKAGES[1][0], checksum="c" * 64)
        with self.assertRaises(ReleaseError):
            publication_state(self.inventory, PACKAGES[2][0], self.registry)

    def test_yank_api_only_index_only_and_network_errors_fail_closed(self):
        name = PACKAGES[0][0]
        for options in ({"yanked": True}, {"index": False}, {"api": False}):
            with self.subTest(options=options):
                self.replies.clear()
                self.publish(name, **options)
                with self.assertRaises(ReleaseError):
                    publication_state(self.inventory, "workspace", self.registry)
        for response in ((401, b""), (503, b""), OSError("network failed")):
            with self.subTest(response=response):
                self.replies.clear()
                self.replies[self.registry.metadata_url(name, "0.2.0")] = response
                with self.assertRaises(ReleaseError):
                    publication_state(self.inventory, "workspace", self.registry)

    def test_pending_exhaustion_and_ambiguous_index_fail(self):
        name = PACKAGES[0][0]
        self.publish(name, index=False)
        with self.assertRaisesRegex(ReleaseError, "pending"):
            publication_state(self.inventory, "workspace", self.registry)
        self.replies.clear()
        self.publish(name)
        url = self.registry.index_url(name)
        self.replies[url] = (200, self.replies[url][1] * 2)
        with self.assertRaisesRegex(ReleaseError, "ambiguous"):
            publication_state(self.inventory, "workspace", self.registry)
        self.replies[url] = (200, b"42\n")
        with self.assertRaises(ReleaseError):
            publication_state(self.inventory, "workspace", self.registry)
        self.replies[url] = (200, json.dumps({"name": "different", "vers": "0.2.0",
                                             "cksum": "b" * 64, "yanked": False}).encode())
        with self.assertRaises(ReleaseError):
            publication_state(self.inventory, "workspace", self.registry)

    def test_wrong_hash_in_one_surface_fails_even_while_other_is_pending(self):
        name = PACKAGES[0][0]
        self.publish(name, checksum="c" * 64, index=False)
        with self.assertRaisesRegex(ReleaseError, "checksum differs"):
            publication_state(self.inventory, "workspace", self.registry)

    def test_inventory_cli_uses_candidate_and_controlled_transport(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "inventory.json"
            path.write_text(json.dumps(self.inventory), encoding="utf-8")
            self.assertEqual(read_inventory(path)["version"], "0.2.0")
            with patch.object(release_checks, "Registry", return_value=self.registry):
                self.assertEqual(release_checks.main(["registry-state", "--inventory", str(path)]), 0)
                self.assertEqual(release_checks.main(["registry-verify", "--inventory", str(path)]), 1)
            path.write_text(path.read_text().replace("pkcs11-proxy-ng-types", "wrong-name"))
            with self.assertRaises(ReleaseError):
                read_inventory(path)
            path.write_text(json.dumps({**self.inventory, "source_commit": "bad"}))
            with self.assertRaises(ReleaseError):
                read_inventory(path)
    def test_verify_incomplete_only_after_selected_matches_and_complete_after_recovery(self):
        name = PACKAGES[0][0]
        with self.assertRaises(ReleaseError):
            verify_publication(self.inventory, self.registry, selected=name)
        self.publish(name)
        # A matching index without matching downloaded bytes is a hard failure.
        with self.assertRaises(ReleaseError):
            verify_publication(self.inventory, self.registry, selected=name)
        import hashlib
        payload = b"verified crate"
        digest = hashlib.sha256(payload).hexdigest()
        for record in self.inventory["packages"]:
            record["sha256"] = digest
        self.replies.clear()
        self.publish(name, checksum=digest)
        self.replies[self.registry.download_url(name, "0.2.0")] = (200, payload)
        self.assertEqual(verify_publication(self.inventory, self.registry, selected=name)["state"], "incomplete")
        for record in self.inventory["packages"][1:]:
            self.publish(record["name"], checksum=digest)
            self.replies[self.registry.download_url(record["name"], "0.2.0")] = (200, payload)
        self.assertEqual(verify_publication(self.inventory, self.registry, selected=name)["state"], "complete")

    def test_registry_consumer_requires_complete_and_uses_verified_downloads(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "inventory.json"
            path.write_text(json.dumps(self.inventory), encoding="utf-8")
            with patch("release.package_consumers._consume", side_effect=AssertionError("must not build")):
                with self.assertRaises(ReleaseError):
                    registry_consumer(ROOT, path, "1.88.0", self.registry)
            for record in self.inventory["packages"]:
                name = record["name"]
                content = io.BytesIO()
                with tarfile.open(fileobj=content, mode="w:gz") as archive:
                    for relative, body in (("Cargo.toml", b"[package]\n"),
                                           ("Cargo.lock", b"version = 4\n")):
                        info = tarfile.TarInfo(f"{name}-0.2.0/{relative}")
                        info.size = len(body)
                        archive.addfile(info, io.BytesIO(body))
                payload = content.getvalue()
                record["sha256"] = hashlib.sha256(payload).hexdigest()
                self.publish(name, checksum=record["sha256"])
                self.replies[self.registry.download_url(name, "0.2.0")] = (200, payload)
            path.write_text(json.dumps(self.inventory), encoding="utf-8")

            def inspect_roots(roots, base, repo, toolchain, version, hashes, *, registry):
                self.assertTrue(registry)
                self.assertEqual(set(roots), {name for name, _ in PACKAGES})
                self.assertEqual(version, "0.2.0")
                for name, root in roots.items():
                    self.assertEqual((root / "Cargo.lock").read_bytes(), b"version = 4\n")
                    self.assertEqual(hashes[name], next(item["sha256"] for item in
                                                         self.inventory["packages"] if item["name"] == name))
                return {"verified_roots": len(roots)}

            with patch("release.package_consumers._consume", side_effect=inspect_roots):
                self.assertEqual(registry_consumer(ROOT, path, "1.88.0", self.registry),
                                 {"verified_roots": 8})

    def test_registry_consumer_executes_locked_registry_only_cargo_path(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as temp:
            path, registry, locks = controlled_registry(Path(temp))
            cargo = ControlledCargo(read_inventory(path), locks)
            with patch("release.package_consumers.subprocess.run", side_effect=cargo):
                result = registry_consumer(ROOT, path, "1.88.0", registry)
            self.assertEqual(cargo.installs, ["pkcs11-proxy-ng", "pkcs11-proxy-ng-cli"])
            self.assertTrue(cargo.shim_built and cargo.exports_loaded)
            self.assertEqual(cargo.checks, [("pkcs11-proxy-ng-client", False),
                                            ("pkcs11-proxy-ng-client", True)])
            self.assertEqual(set(cargo.docs), {
                "pkcs11-proxy-ng-types", "pkcs11-proxy-ng-audit", "pkcs11-proxy-ng-proto",
                "pkcs11-proxy-ng-client", "pkcs11-proxy-ng-backend", "pkcs11-proxy-ng",
                "pkcs11-proxy-ng-shim"})
            self.assertEqual(result["pkcs11-proxy-ng"]["installed_version"],
                             "pkcs11-proxy-ng 0.2.0")
            self.assertEqual(result["pkcs11-proxy-ng-cli"]["installed_version"],
                             "pkcs11-proxy-ng-cli 0.2.0")
            self.assertEqual(len(result["pkcs11-proxy-ng-shim"]["exports"]), 3)
            for invalid in ("local_dependency", "mutate_lock", "wrong_client_version"):
                with self.subTest(invalid=invalid):
                    broken = ControlledCargo(read_inventory(path), locks, **{invalid: True})
                    with patch("release.package_consumers.subprocess.run", side_effect=broken):
                        with self.assertRaises(ReleaseError):
                            registry_consumer(ROOT, path, "1.88.0", registry)


if __name__ == "__main__":
    unittest.main()

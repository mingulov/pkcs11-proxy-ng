"""Registry-bound release binary build boundaries."""

from pathlib import Path
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from release.package_model import ReleaseError  # noqa: E402
from release.package_binaries import (  # noqa: E402
    build_binaries, release_environment, validate_version_line, validate_build_graph,
    target_command, require_registry_provenance, validate_release_profile,
)
from release.package_registry import read_inventory  # noqa: E402
from release.package_consumers import registry_consumer  # noqa: E402
from test_release_registry import controlled_registry, ControlledCargo  # noqa: E402
import release_checks  # noqa: E402


class BinaryBoundaryTests(unittest.TestCase):
    def test_version_line_rejects_banner_or_wrong_executable(self):
        validate_version_line("pkcs11-proxy-ng 0.2.0\n", "pkcs11-proxy-ng", "0.2.0")
        for text in ("banner\npkcs11-proxy-ng 0.2.0\n", "other 0.2.0\n",
                     "pkcs11-proxy-ng 0.2.0 extra\n", "pkcs11-proxy-ng 0.3.0\n",
                     "pkcs11-proxy-ng 0.2.0\npkcs11-proxy-ng 0.2.0\n"):
            with self.subTest(text=text), self.assertRaises(ReleaseError):
                validate_version_line(text, "pkcs11-proxy-ng", "0.2.0")

    def test_environment_discards_inherited_build_and_source_overrides(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            inherited = {"PATH": os.environ["PATH"], "HOME": str(root),
                         "CARGO_PROFILE_RELEASE_PANIC": "abort", "CARGO_BUILD_TARGET": "i686-unknown-linux-gnu",
                         "CARGO_ENCODED_RUSTFLAGS": "-C\x1flink-arg=-bad", "RUSTFLAGS": "-C panic=abort",
                         "RUSTC": "/tmp/wrong-rustc", "CARGO_SOURCE_CRATES_IO_REPLACE_WITH": "vendor",
                         "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER": "/tmp/wrong-linker"}
            env = release_environment(root, "x86_64-pc-windows-msvc", inherited)
            for name in inherited.keys() - {"PATH", "HOME"}:
                self.assertNotEqual(env.get(name), inherited[name], name)
            self.assertEqual(env["CARGO_TARGET_DIR"], str(root / "target"))
            self.assertEqual(env["CARGO_BUILD_BUILD_DIR"], str(root / "build"))
            self.assertEqual(env["CARGO_PROFILE_RELEASE_LTO"], "thin")
            self.assertEqual(env["CARGO_PROFILE_RELEASE_STRIP"], "symbols")
            self.assertEqual(env["CARGO_PROFILE_RELEASE_CODEGEN_UNITS"], "1")
            self.assertEqual(env["CARGO_PROFILE_RELEASE_PANIC"], "unwind")

    def test_target_command_is_locked_and_separates_windows_example(self):
        root = Path("/tmp/source/Cargo.toml")
        linux = target_command("1.98.1", "x86_64-unknown-linux-gnu", root, "pkcs11-proxy-ng", "bin")
        windows = target_command("1.98.1", "x86_64-pc-windows-msvc", root, "cross_width_smoke", "example")
        self.assertEqual(linux[:3], ["cargo", "+1.98.1", "build"])
        self.assertEqual(windows[:4], ["cargo", "+1.98.1", "xwin", "build"])
        for command in (linux, windows):
            self.assertIn("--locked", command)
            self.assertIn("--release", command)
            self.assertIn("--manifest-path", command)
            self.assertNotIn("--all-features", command)
        self.assertEqual(windows[-2:], ["--example", "cross_width_smoke"])
        shim = target_command("1.98.1", "x86_64-unknown-linux-gnu", root,
                              "pkcs11-proxy-ng-shim", "lib")
        self.assertEqual(shim[-1], "--lib")
        self.assertNotIn("pkcs11-proxy-ng-shim", shim)
        configured = target_command("1.98.1", "x86_64-pc-windows-msvc", root,
                                    "pkcs11-proxy-ng", "bin",
                                    ["--config", 'patch.crates-io.pkcs11-proxy-ng-types.path="/tmp/types"'])
        self.assertEqual(configured[2:6], ["xwin", "build", "--config",
                                           'patch.crates-io.pkcs11-proxy-ng-types.path="/tmp/types"'])

    def test_profile_must_retain_current_unwind_release_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = root / "Cargo.toml"
            manifest.write_text('[profile.release]\nlto = "thin"\nstrip = "symbols"\ncodegen-units = 1\n')
            validate_release_profile(root)
            manifest.write_text('[profile.release]\nlto = "thin"\nstrip = "symbols"\ncodegen-units = 1\npanic = "abort"\n')
            with self.assertRaises(ReleaseError):
                validate_release_profile(root)

    def test_candidate_provenance_cannot_pass_registry_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "build-provenance.json"
            path.write_text(json.dumps({"format_version": 1, "source_mode": "archive",
                                        "github_publication_eligible": False}))
            with self.assertRaises(ReleaseError):
                require_registry_provenance(path)
            path.write_text(json.dumps({"format_version": 1, "source_mode": "registry",
                                        "github_publication_eligible": True}))
            require_registry_provenance(path)

    def test_build_graph_rejects_checkout_roots_and_unexpected_features(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            unpack = base / "unpacked"
            root = unpack / "pkcs11-proxy-ng-0.2.0"
            root.mkdir(parents=True)
            (root / "Cargo.toml").write_text('[package]\nname = "pkcs11-proxy-ng"\nversion = "0.2.0"\n')
            root_id = "path+file:///root#0.2.0"
            metadata = {"packages": [{"id": root_id, "name": "pkcs11-proxy-ng", "version": "0.2.0",
                                      "source": None, "manifest_path": str(root / "Cargo.toml")}],
                        "resolve": {"nodes": [{"id": root_id, "features": [], "deps": []}]}}
            validate_build_graph(metadata, unpack, "pkcs11-proxy-ng", "0.2.0", "registry",
                                 {"pkcs11-proxy-ng": set()})
            with self.assertRaises(ReleaseError):
                validate_build_graph(metadata, unpack, "pkcs11-proxy-ng", "0.2.0", "registry",
                                     {"pkcs11-proxy-ng": {"native-owner-test-hooks"}})
            metadata["packages"][0]["manifest_path"] = str(base / "checkout/Cargo.toml")
            with self.assertRaises(ReleaseError):
                validate_build_graph(metadata, unpack, "pkcs11-proxy-ng", "0.2.0", "registry",
                                     {"pkcs11-proxy-ng": set()})


class ControlledBinaryBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.inventory_path, self.registry, self.locks = controlled_registry(self.base)
        self.inventory = read_inventory(self.inventory_path)
        self.packages = self.base / "packages"
        self.packages.mkdir()
        # The registry fixture uses real tar/checksum/lock parsing. Add the
        # required published shim example without touching its lock graph.
        shim = "pkcs11-proxy-ng-shim"
        url = self.registry.download_url(shim, "0.2.0")
        _, payload = self.registry.transport.replies[url]
        files = {}
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as source:
            for member in source:
                files[member.name.split("/", 1)[1]] = source.extractfile(member).read()
        files["examples/cross_width_smoke.rs"] = b"fn main() {}\n"
        self.rewrite_shim(files)
        self.inventory_path.write_text(json.dumps(self.inventory))
        for record in self.inventory["packages"]:
            _, body = self.registry.transport.replies[self.registry.download_url(record["name"], "0.2.0")]
            (self.packages / record["archive"]).write_bytes(body)

    def rewrite_shim(self, files):
        shim = "pkcs11-proxy-ng-shim"
        url = self.registry.download_url(shim, "0.2.0")
        content = io.BytesIO()
        with tarfile.open(fileobj=content, mode="w:gz") as archive:
            for relative, body in files.items():
                member = tarfile.TarInfo(f"{shim}-0.2.0/{relative}")
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
        self.registry.transport.replies[url] = (200, content.getvalue())
        digest = hashlib.sha256(content.getvalue()).hexdigest()
        record = next(item for item in self.inventory["packages"] if item["name"] == shim)
        record["sha256"] = digest
        record["files"] = sorted(files)
        self.registry.transport.replies[self.registry.metadata_url(shim, "0.2.0")] = (
            200, json.dumps({"version": {"num": "0.2.0", "checksum": digest, "yanked": False}}).encode())
        self.registry.transport.replies[self.registry.index_url(shim)] = (
            200, json.dumps({"name": shim, "vers": "0.2.0", "cksum": digest, "yanked": False}).encode() + b"\n")
        self.inventory_path.write_text(json.dumps(self.inventory))
        (self.packages / record["archive"]).write_bytes(content.getvalue())

    def fake_process(self, command, *, cwd=None, env=None, **_kwargs):
        if command[:2] == ["rustc", "+1.98.1"]:
            output = str(self.base / "sysroot") + "\n" if "--print" in command else "rustc 1.98.1 (test)\n"
            return subprocess.CompletedProcess(command, 0, output, "")
        if command[:2] == ["cargo", "+1.98.1"] and "--version" in command:
            return subprocess.CompletedProcess(command, 0, "cargo 1.98.1 (test)\n", "")
        if command[:2] == ["cargo", "xwin"] and "--version" in command:
            return subprocess.CompletedProcess(command, 0, "cargo-xwin-xwin 0.23.1\n", "")
        if command[0] == "protoc":
            return subprocess.CompletedProcess(command, 0, "libprotoc 33.0\n", "")
        if command[0] != "cargo":
            return subprocess.CompletedProcess(command, 0,
                                               f"{Path(command[0]).name} 0.2.0\n", "")
        self.assertEqual(command[1], "+1.98.1")
        self.assertIn("--locked", command)
        self.assertNotIn("--all-features", command)
        self.assertNotIn("--config", command)
        self.assertEqual(env["CARGO_PROFILE_RELEASE_PANIC"], "unwind")
        cwd = Path(cwd)
        root = cwd.name.removesuffix("-0.2.0")
        if "metadata" in command:
            metadata = json.loads(self.cargo._metadata(root, cwd, env))
            if getattr(self, "local_source", False) and root == "pkcs11-proxy-ng":
                package = next(p for p in metadata["packages"] if p["name"] == "pkcs11-proxy-ng-types")
                package["source"] = None
                package["manifest_path"] = str(ROOT / "crates/types/Cargo.toml")
            if getattr(self, "mutate_lock", False) and root == "pkcs11-proxy-ng":
                (cwd / "Cargo.lock").write_bytes(self.locks[root] + b"\n")
            return subprocess.CompletedProcess(command, 0, json.dumps(metadata), "")
        if "tree" in command:
            lines = [f"{name} v0.2.0|" for name in sorted(self.cargo._closure(root))]
            return subprocess.CompletedProcess(command, 0, "\n".join(lines) + "\n", "")
        self.assertIn("build", command)
        name = root if "--lib" in command else command[-1]
        target = command[command.index("--target") + 1]
        extension = ".exe" if "windows" in target and name != "pkcs11-proxy-ng-shim" else ""
        output_name = "pkcs11_proxy_ng_shim.dll" if "windows" in target and name == "pkcs11-proxy-ng-shim" else (
            "libpkcs11_proxy_ng_shim.so" if name == "pkcs11-proxy-ng-shim" else name + extension)
        artifact = Path(env["CARGO_TARGET_DIR"]) / target / "release" / ("examples" if "--example" in command else "") / output_name
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(b"controlled build " + output_name.encode())
        return subprocess.CompletedProcess(command, 0, "", "")

    def build(self, target="x86_64-pc-windows-msvc", *, source="registry"):
        self.cargo = ControlledCargo(self.inventory, self.locks)
        with patch("release.package_binaries.inspect_archives", return_value=self.inventory), \
             patch("release.package_binaries.subprocess.run", side_effect=self.fake_process):
            return build_binaries(ROOT, self.inventory_path, self.packages, source, target,
                                  self.base / "output", "1.98.1", registry=self.registry)

    def test_registry_fixture_runs_source_lock_graph_and_build_orchestration(self):
        result = self.build()
        self.assertEqual(result["source_mode"], "registry")
        artifacts = json.loads((self.base / "output/build-provenance.json").read_text())["artifacts"]
        self.assertEqual(len(artifacts), 4)
        self.assertTrue((self.base / "output/binaries/cross_width_smoke.exe").is_file())
        inputs = json.loads((self.base / "output/build-inputs.json").read_text())
        self.assertEqual(set(inputs["graphs"]), {"pkcs11-proxy-ng", "pkcs11-proxy-ng-cli",
                                                "pkcs11-proxy-ng-shim"})
        self.assertEqual(inputs["cargo_home"], str(self.base / "output/session/cargo-home"))
        self.assertEqual(inputs["rust_sysroot"], str(self.base / "sysroot"))
        self.assertNotIn(str(self.base), (self.base / "output/build-provenance.json").read_text())
        for name in ("pkcs11-proxy-ng", "pkcs11-proxy-ng-cli", "pkcs11-proxy-ng-shim"):
            self.assertEqual((self.base / "output/unpacked" / f"{name}-0.2.0/Cargo.lock").read_bytes(),
                             self.locks[name])

    def test_missing_or_yanked_registry_member_blocks_build(self):
        name = "pkcs11-proxy-ng-types"
        for state in ("missing", "yanked"):
            with self.subTest(state=state):
                url = self.registry.metadata_url(name, "0.2.0")
                old = self.registry.transport.replies[url]
                self.registry.transport.replies[url] = (404, b"") if state == "missing" else (
                    200, json.dumps({"version": {"num": "0.2.0", "checksum": self.inventory["packages"][0]["sha256"],
                                          "yanked": True}}).encode())
                with self.assertRaises(ReleaseError):
                    self.build()
                self.registry.transport.replies[url] = old
                # A failed fresh output is deliberately retained for diagnosis.
                self.base.joinpath("output").rename(self.base / f"failed-{state}")

    def test_refuses_existing_output_before_registry_access(self):
        (self.base / "output").mkdir()
        with self.assertRaises(ReleaseError):
            self.build()

    def test_registry_rejects_local_source_or_mutated_packaged_lock(self):
        for issue in ("local_source", "mutate_lock"):
            with self.subTest(issue=issue):
                setattr(self, issue, True)
                with self.assertRaises(ReleaseError):
                    self.build()
                setattr(self, issue, False)
                self.base.joinpath("output").rename(self.base / f"failed-{issue}")

    def test_registry_checksum_mismatch_blocks_build(self):
        name = "pkcs11-proxy-ng-types"
        url = self.registry.index_url(name)
        self.registry.transport.replies[url] = (
            200, json.dumps({"name": name, "vers": "0.2.0", "cksum": "f" * 64,
                             "yanked": False}).encode() + b"\n")
        with self.assertRaises(ReleaseError):
            self.build()

    def test_windows_requires_published_shim_example(self):
        _, payload = self.registry.transport.replies[
            self.registry.download_url("pkcs11-proxy-ng-shim", "0.2.0")]
        files = {}
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            for member in archive:
                relative = member.name.split("/", 1)[1]
                if relative != "examples/cross_width_smoke.rs":
                    files[relative] = archive.extractfile(member).read()
        self.rewrite_shim(files)
        with self.assertRaisesRegex(ReleaseError, "cross_width_smoke"):
            self.build()

    def test_wrong_toolchain_and_target_refused_before_output(self):
        for target, toolchain in (("i686-unknown-linux-gnu", "1.98.1"),
                                  ("x86_64-unknown-linux-gnu", "1.88.0")):
            with self.subTest(target=target, toolchain=toolchain), self.assertRaises(ReleaseError):
                build_binaries(ROOT, self.inventory_path, self.packages, "registry", target,
                               self.base / "output", toolchain, registry=self.registry)
            self.assertFalse((self.base / "output").exists())

    def test_cli_dispatches_binary_build_contract(self):
        args = ["binary-build", "--inventory", str(self.inventory_path), "--package-dir",
                str(self.packages), "--source", "archive", "--target", "x86_64-unknown-linux-gnu",
                "--output", str(self.base / "staged"), "--toolchain", "1.98.1"]
        with patch("release_checks.build_binaries", return_value={"source_mode": "archive"}) as build:
            self.assertEqual(release_checks.main(args, repo=ROOT), 0)
        build.assert_called_once_with(ROOT, self.inventory_path, self.packages, "archive",
                                      "x86_64-unknown-linux-gnu", self.base / "staged", "1.98.1")

    def test_consumer_refuses_version_banner_with_expected_suffix(self):
        class BannerCargo(ControlledCargo):
            def __call__(self, command, **kwargs):
                result = super().__call__(command, **kwargs)
                if command[0] != "cargo" and command[-1] == "--version":
                    return subprocess.CompletedProcess(command, 0, "untrusted banner\n" + result.stdout, "")
                return result

        cargo = BannerCargo(self.inventory, self.locks)
        with patch("release.package_consumers.subprocess.run", side_effect=cargo):
            with self.assertRaises(ReleaseError):
                registry_consumer(ROOT, self.inventory_path, "1.88.0", self.registry)


if __name__ == "__main__":
    unittest.main()

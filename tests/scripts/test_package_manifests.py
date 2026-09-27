"""Checks for the standalone crates.io source-package contract."""

import json
from pathlib import Path
import subprocess
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
CRATES = ("audit", "types", "proto", "backend", "server", "client", "cli", "shim")
PREFIX = "pkcs11-proxy-ng-"
EDGES = {
    "audit": set(),
    "types": set(),
    "proto": {"types"},
    "backend": {"types", "proto"},
    "server": {"types", "proto", "backend", "audit"},
    "client": {"types", "proto"},
    "cli": {"types", "client", "audit"},
    "shim": {"types", "client", "proto"},
}


class PackageManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        command = ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"]
        cls.metadata = json.loads(subprocess.check_output(command, cwd=ROOT, text=True))

    def test_eight_publishable_packages_with_complete_local_material(self):
        packages = {package["name"]: package for package in self.metadata["packages"]}
        expected = {"pkcs11-proxy-ng"} | {PREFIX + crate for crate in CRATES if crate != "server"}
        self.assertEqual(set(packages), expected)
        root_apache = (ROOT / "LICENSE-APACHE").read_bytes()
        root_mit = (ROOT / "LICENSE-MIT").read_bytes()
        for crate in CRATES:
            with self.subTest(crate=crate):
                package = packages["pkcs11-proxy-ng" if crate == "server" else PREFIX + crate]
                directory = ROOT / "crates" / crate
                manifest = tomllib.loads((directory / "Cargo.toml").read_text())
                self.assertEqual(package["version"], "0.2.0")
                self.assertEqual(package["publish"], ["crates-io"])
                self.assertEqual(package["repository"], "https://github.com/mingulov/pkcs11-proxy-ng")
                self.assertEqual(package["readme"], "README.md")
                self.assertTrue(package["description"])
                self.assertTrue(package["categories"])
                self.assertTrue(package["keywords"])
                self.assertEqual((directory / "LICENSE-APACHE").read_bytes(), root_apache)
                self.assertEqual((directory / "LICENSE-MIT").read_bytes(), root_mit)
                included = set(manifest["package"].get("include", []))
                self.assertTrue({"Cargo.toml", "README.md", "LICENSE-APACHE", "LICENSE-MIT", "src/**"} <= included)
                self.assertEqual(package["edition"], "2024")
                self.assertEqual(package["rust_version"], "1.88")

    def test_internal_edges_are_exact_and_dev_edges_stay_path_only(self):
        for crate in CRATES:
            with self.subTest(crate=crate):
                manifest = tomllib.loads((ROOT / "crates" / crate / "Cargo.toml").read_text())
                for section in ("dependencies", "build-dependencies"):
                    actual = set()
                    for name, spec in manifest.get(section, {}).items():
                        if name.startswith(PREFIX) or name == "pkcs11-proxy-ng":
                            actual.add("server" if name == "pkcs11-proxy-ng" else name.removeprefix(PREFIX))
                            self.assertEqual(spec.get("version"), "=0.2.0", name)
                            self.assertTrue(spec["path"], name)
                    if section == "dependencies":
                        self.assertEqual(actual, EDGES[crate])
                for name, spec in manifest.get("dev-dependencies", {}).items():
                    if name.startswith(PREFIX) or name == "pkcs11-proxy-ng":
                        self.assertTrue(spec["path"], name)
                        self.assertNotIn("version", spec, name)

    def test_targets_and_proto_build_inputs_survive_packaging(self):
        packages = {package["name"]: package for package in self.metadata["packages"]}
        self.assertIn(("pkcs11-proxy-ng", ("bin",)),
                      {(target["name"], tuple(target["kind"])) for target in packages["pkcs11-proxy-ng"]["targets"]})
        self.assertIn(("pkcs11-proxy-ng-cli", ("bin",)),
                      {(target["name"], tuple(target["kind"])) for target in packages[PREFIX + "cli"]["targets"]})
        self.assertIn(("pkcs11_proxy_ng_shim", ("cdylib", "rlib")),
                      {(target["name"], tuple(target["kind"])) for target in packages[PREFIX + "shim"]["targets"]})
        for crate in CRATES:
            if crate not in ("cli",):
                package = packages["pkcs11-proxy-ng" if crate == "server" else PREFIX + crate]
                self.assertTrue(any("lib" in target["kind"] or "rlib" in target["kind"] for target in package["targets"]))
        proto = ROOT / "crates/proto"
        included = set(tomllib.loads((proto / "Cargo.toml").read_text())["package"].get("include", []))
        self.assertTrue({"build.rs", "secret-fields.toml", "proto/**"} <= included)
        for name in ("service", "types", "mechanism_params"):
            self.assertTrue((proto / "proto/pkcs11-proxy-ng/v1" / (name + ".proto")).is_file())
        self.assertFalse((ROOT / "proto/pkcs11-proxy-ng/v1/service.proto").exists())

    def test_readmes_explain_build_tools_and_repository_test_boundary(self):
        for crate in CRATES:
            with self.subTest(crate=crate):
                readme = (ROOT / "crates" / crate / "README.md").read_text()
                for required in (
                    "Rust 1.88",
                    "C compiler",
                    "pkg-config",
                    "protoc",
                    "cargo install",
                    "example",
                    "standalone Git checkout",
                    "cargo test --workspace",
                    "repository-only tests",
                ):
                    self.assertIn(required, readme)


if __name__ == "__main__":
    unittest.main()

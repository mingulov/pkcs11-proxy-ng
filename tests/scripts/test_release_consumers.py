"""Archive consumer identity and graph boundaries."""

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from release.package_model import ReleaseError  # noqa: E402
from release.package_consumers import _patches, _seed_lock, reconcile_lock, validate_metadata  # noqa: E402


class ConsumerIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.unpack = self.root / "unpacked"
        self.unpack.mkdir()
        self.client = self.unpack / "pkcs11-proxy-ng-client-0.2.0"
        self.types = self.unpack / "pkcs11-proxy-ng-types-0.2.0"
        self.client.mkdir()
        self.types.mkdir()
        self.source = "registry+https://github.com/rust-lang/crates.io-index"
        self.external = {("serde", "1.0.0", self.source, "a" * 64)}

    def test_reconcile_lock_requires_external_identity_and_internal_members(self):
        valid = {"package": [
            {"name": "serde", "version": "1.0.0", "source": self.source,
             "checksum": "a" * 64},
            {"name": "pkcs11-proxy-ng-types", "version": "0.2.0"},
            {"name": "pkcs11-proxy-ng-client", "version": "0.2.0"},
        ]}
        reconcile_lock(valid, self.external, "0.2.0",
                       {"pkcs11-proxy-ng-types", "pkcs11-proxy-ng-client"})
        for changed in ("version", "checksum"):
            with self.subTest(changed=changed):
                bad = {"package": [dict(item) for item in valid["package"]]}
                bad["package"][0][changed] = "1.0.1" if changed == "version" else "b" * 64
                with self.assertRaises(ReleaseError):
                    reconcile_lock(bad, self.external, "0.2.0",
                                   {"pkcs11-proxy-ng-types", "pkcs11-proxy-ng-client"})
        with self.assertRaises(ReleaseError):
            reconcile_lock({"package": valid["package"][:1]}, self.external,
                           "0.2.0", {"pkcs11-proxy-ng-types"})

    def test_archive_patch_seed_changes_only_internal_lock_source(self):
        original = ('version = 4\n[[package]]\nname = "pkcs11-proxy-ng-client"\n'
                    'version = "0.2.0"\n[[package]]\nname = "pkcs11-proxy-ng-types"\n'
                    'version = "0.2.0"\nsource = "' + self.source + '"\n'
                    'checksum = "' + "b" * 64 + '"\n[[package]]\nname = "serde"\n'
                    'version = "1.0.0"\nsource = "' + self.source + '"\n'
                    'checksum = "' + "a" * 64 + '"\n')
        source = self.root / "original.lock"
        output = self.root / "seeded.lock"
        source.write_text(original)
        _seed_lock(source, output, self.external, "0.2.0",
                   {"pkcs11-proxy-ng-types": "b" * 64,
                    "pkcs11-proxy-ng-client": "c" * 64},
                   {"pkcs11-proxy-ng-types", "pkcs11-proxy-ng-client"})
        seeded = output.read_text()
        self.assertIn('name = "serde"\nversion = "1.0.0"\nsource = "' + self.source +
                      '"\nchecksum = "' + "a" * 64 + '"', seeded)
        self.assertNotIn('checksum = "' + "b" * 64 + '"', seeded)
        self.assertEqual(source.read_text(), original)

    def test_patch_list_contains_only_locked_internal_dependencies(self):
        roots = {"pkcs11-proxy-ng-client": self.client,
                 "pkcs11-proxy-ng-types": self.types,
                 "pkcs11-proxy-ng": self.unpack / "pkcs11-proxy-ng-0.2.0"}
        args = _patches(roots, "pkcs11-proxy-ng-client", {"pkcs11-proxy-ng-types"})
        self.assertEqual(len(args), 2)
        self.assertEqual(args[0], "--config")
        self.assertIn("pkcs11-proxy-ng-types", args[1])
        self.assertNotIn("pkcs11-proxy-ng-0.2.0", args[1])

    def metadata(self, *, client_path=None, types_path=None, types_version="0.2.0",
                 extra=(), features=None):
        return {"packages": [
            {"id": "path+file:///client#0.2.0", "name": "pkcs11-proxy-ng-client",
             "version": "0.2.0", "source": None,
             "manifest_path": str((client_path or self.client) / "Cargo.toml")},
            {"id": "path+file:///types#0.2.0", "name": "pkcs11-proxy-ng-types",
             "version": types_version, "source": None,
             "manifest_path": str((types_path or self.types) / "Cargo.toml")},
            *extra,
        ], "resolve": {"nodes": [
            {"id": "path+file:///client#0.2.0", "features": [],
             "deps": [{"pkg": "path+file:///types#0.2.0", "dep_kinds": [{"kind": None}]}]},
            {"id": "path+file:///types#0.2.0", "features": features or [], "deps": []},
        ]}}

    def test_rejects_checkout_leak_missing_or_wrong_internal_package(self):
        validate_metadata(self.metadata(), self.unpack, "pkcs11-proxy-ng-client", "0.2.0", "archive")
        for graph in (
            self.metadata(types_path=self.root / "checkout"),
            {**self.metadata(), "packages": self.metadata()["packages"][:1]},
            self.metadata(types_version="0.1.0"),
        ):
            with self.subTest(graph=graph):
                with self.assertRaises(ReleaseError):
                    validate_metadata(graph, self.unpack, "pkcs11-proxy-ng-client", "0.2.0", "archive")

    def test_thin_client_rejects_backend_and_server_transport_features(self):
        server = {"id": "registry+server#0.2.0", "name": "pkcs11-proxy-ng",
                  "version": "0.2.0", "source": self.source,
                  "manifest_path": str(self.root / "registry/server/Cargo.toml")}
        graph = self.metadata(extra=(server,))
        graph["resolve"]["nodes"][0]["deps"].append(
            {"pkg": server["id"], "dep_kinds": [{"kind": None}]})
        with self.assertRaises(ReleaseError):
            validate_metadata(graph, self.unpack, "pkcs11-proxy-ng-client", "0.2.0", "archive")
        for name, feature in (("tonic", "server"), ("tokio", "signal"), ("hyper", "server")):
            with self.subTest(name=name, feature=feature):
                graph = self.metadata()
                graph["packages"].append({"id": f"registry+{name}", "name": name,
                                          "version": "1.0.0", "source": self.source,
                                          "manifest_path": str(self.root / f"registry/{name}/Cargo.toml")})
                graph["resolve"]["nodes"].append({"id": f"registry+{name}", "features": [feature], "deps": []})
                graph["resolve"]["nodes"][0]["deps"].append(
                    {"pkg": f"registry+{name}", "dep_kinds": [{"kind": None}]})
                with self.assertRaises(ReleaseError):
                    validate_metadata(graph, self.unpack, "pkcs11-proxy-ng-client", "0.2.0", "archive")

    def test_registry_graph_rejects_local_internal_dependency(self):
        graph = self.metadata()
        with self.assertRaises(ReleaseError):
            validate_metadata(graph, self.unpack, "pkcs11-proxy-ng-client", "0.2.0", "registry")


if __name__ == "__main__":
    unittest.main()

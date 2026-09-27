"""Controlled registry publication and recovery cases."""

from pathlib import Path
import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from release.package_model import PACKAGES, ReleaseError  # noqa: E402
from release.package_registry import Registry, publication_state, read_inventory, verify_publication  # noqa: E402
from release.package_consumers import registry_consumer  # noqa: E402
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


if __name__ == "__main__":
    unittest.main()

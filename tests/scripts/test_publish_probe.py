"""Generated probe is isolated from the production Cargo workspace."""

from pathlib import Path
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import release_checks  # noqa: E402


class PublishProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.destination = Path(self.temp.name) / "probe"

    def check(self, *args):
        return release_checks.main(["staging-probe", "--destination", str(self.destination),
                                    "--run-id", "123", "--attempt", "2", *args], repo=ROOT)

    def test_generates_unique_staging_only_dependency_free_probe(self):
        self.assertEqual(self.check(), 0)
        manifest = tomllib.loads((self.destination / "Cargo.toml").read_text())
        self.assertEqual(manifest["package"]["name"], "pkcs11-proxy-ng-publish-probe")
        self.assertEqual(manifest["package"]["version"], "0.0.0-ci.123.2")
        self.assertEqual(manifest["package"]["publish"], ["staging"])
        self.assertEqual(manifest["workspace"], {})
        self.assertNotIn("dependencies", manifest)
        self.assertTrue((self.destination / "src/lib.rs").exists())
        self.assertEqual(self.check(), 1)

    def test_rejects_invalid_ids_and_production_registry(self):
        for args in (("--run-id", "0"), ("--run-id", "-1"), ("--run-id", "abc"),
                     ("--attempt", "0"), ("--attempt", "1.2"),
                     ("--registry", "crates-io")):
            with self.subTest(args=args):
                self.assertEqual(self.check(*args), 1)
                self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()

"""Checks public source and distribution boundaries without external checkouts."""

import hashlib
from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
PROJECT = "https://github.com/mingulov/pkcs11-proxy-ng"
class SourceProvenanceTests(unittest.TestCase):
    def test_public_source_tree_has_no_oasis_document_tools_or_project_notice(self):
        for relative in (
            "scripts/oasis-coverage-inventory.py",
            "scripts/gen-historical-mechanism-flags.py",
            "crates/backend/NOTICE",
        ):
            with self.subTest(path=relative):
                self.assertFalse((ROOT / relative).exists(), relative)
        manifest = tomllib.loads((ROOT / "crates/backend/Cargo.toml").read_text())
        self.assertNotIn("NOTICE", manifest["package"]["include"])

    def test_committed_mock_table_body_is_stable(self):
        generated = (ROOT / "crates/backend/src/mock/historical_flags.rs").read_text()
        self.assertEqual(
            hashlib.sha256(generated[generated.index("pub(super) fn historical_workflow_flags"):].encode()).hexdigest(),
            "bfc2ecd7fe6537fa05f1c24b5d013e9c832be5a0d6145b36fe6099e4d60b50cb",
        )
        self.assertEqual(
            sum(1 for line in generated.splitlines() if line.lstrip().startswith("0x") and " => " in line),
            105,
        )

    def test_source_and_distribution_boundaries_are_documented(self):
        licensing = (ROOT / "doc/release/licensing.md").read_text()
        for required in ("c5e61990c5621a9b955fc208644fe8145ac0a75d", "operator-supplied", "binary", "dependency"):
            with self.subTest(required=required):
                self.assertIn(required, licensing)
        self.assertIn("external", (ROOT / "doc/oasis-profile-coverage.md").read_text())

    def test_public_packaging_metadata_uses_project_identity(self):
        paths = (
            "packaging/alpine/APKBUILD",
            "packaging/amazon/pkcs11-proxy-ng.spec",
            "packaging/alpine/Dockerfile.alpine",
            "packaging/amazon/Dockerfile.amazon",
        )
        for name in paths:
            with self.subTest(path=name):
                text = (ROOT / name).read_text()
                self.assertNotIn("gitlab.com/", text)
                self.assertIn(PROJECT, text)

    def test_soft_hsm_patch_and_image_retain_upstream_license(self):
        patch_dir = ROOT / "tests/consumers/backends/softhsm2-patched"
        provenance = (patch_dir / "PROVENANCE.md").read_text()
        for required in ("SoftHSMv2", "2.6.1", "LICENSE", "cloudhsm-aes-gcm.patch"):
            self.assertIn(required, provenance)
        license_text = (patch_dir / "LICENSE-SoftHSM").read_text()
        self.assertIn("Copyright (c) 2010 .SE", license_text)
        self.assertIn("Redistributions in binary form must reproduce", license_text)
        self.assertIn("THIS SOFTWARE IS PROVIDED BY THE AUTHOR", license_text)
        image = (ROOT / "tests/consumers/Dockerfile.daemon.softhsm2-patched").read_text()
        self.assertIn("COPY --from=softhsm-builder /src/softhsm/LICENSE", image)


if __name__ == "__main__":
    unittest.main()

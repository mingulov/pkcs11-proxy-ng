"""Checks for source notice and provenance material without external checkouts."""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
PROJECT = "https://github.com/mingulov/pkcs11-proxy-ng"
HISTORICAL = "https://docs.oasis-open.org/pkcs11/pkcs11-hist/v3.0/os/pkcs11-hist-v3.0-os.html"
HIST_HASH = "53db1b1fe37e61d74ea2bc86742019e85a25aac8fc648e884abbb204858cf47c"
HEADER_HASH = "5b58736b6d23f12b4d9492cd24b06b9d11056c3153afc4e89b1fe564749e71a2"


class SourceProvenanceTests(unittest.TestCase):
    def test_generator_refuses_unpinned_numeric_header_without_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "repo/scripts/gen-historical-mechanism-flags.py"
            script.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / "scripts/gen-historical-mechanism-flags.py", script)
            historical = root / "doc/pkcs11-oasis/pkcs11-hist/v3.0/pkcs11-hist-v3.0.html"
            historical.parent.mkdir(parents=True)
            historical.write_text("<tr><td>CKM_RSA_PKCS</td><td>x</td></tr>")
            header = root / "doc/oasis-tcs-pkcs11/published/2-40-errata-1/pkcs11t.h"
            header.parent.mkdir(parents=True)
            header.write_text("#define CKM_RSA_PKCS 0x00000001UL\n")
            env = os.environ.copy()
            env["PKCS11_PROXY_NG_OASIS_ROOT"] = str(root / "doc/pkcs11-oasis")
            result = subprocess.run(
                [sys.executable, str(script)], env=env, text=True,
                capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertIn("numeric header SHA-256 mismatch", result.stderr)

    def test_backend_archive_declares_complete_historical_notice(self):
        manifest = tomllib.loads((ROOT / "crates/backend/Cargo.toml").read_text())
        self.assertIn("NOTICE", manifest["package"]["include"])
        notice = (ROOT / "crates/backend/NOTICE").read_text()
        self.assertIn(HISTORICAL, notice)
        self.assertIn("Copyright © OASIS Open 2020. All Rights Reserved.", notice)
        self.assertIn("The limited permissions granted above are perpetual", notice)
        self.assertIn("The name \"OASIS\" is a trademark", notice)

    def test_generator_and_generated_header_identify_actual_inputs(self):
        generator = (ROOT / "scripts/gen-historical-mechanism-flags.py").read_text()
        generated = (ROOT / "crates/backend/src/mock/historical_flags.rs").read_text()
        for text in (generator, generated):
            with self.subTest(source=text[:40]):
                for required in (HISTORICAL, HIST_HASH, HEADER_HASH, "crates/backend/NOTICE"):
                    self.assertIn(required, text)
        self.assertEqual(
            hashlib.sha256(generated[generated.index("use pkcs11_proxy_ng_types"):].encode()).hexdigest(),
            "043c738395a763fdd10b70aad4320556f9c3b287cbbed99f2decd1841da4b967",
        )

    def test_source_and_distribution_boundaries_are_documented(self):
        licensing = (ROOT / "doc/release/licensing.md").read_text()
        for required in (HISTORICAL, HIST_HASH, HEADER_HASH, "c5e61990c5621a9b955fc208644fe8145ac0a75d", "operator-supplied", "binary", "dependency"):
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

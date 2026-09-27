"""Unit tests for scripts/ci-package-smoke.py (Stage B, Task 5a).

The smoke contract is reusable: the same entry points verify
archive-built bundles in CI today and registry release bundles before
GitHub asset approval later. Provider-dependent paths (real SoftHSM
token, daemon start, pkcs11-tool / cross_width_smoke execution) are
exercised through mocks here and at runtime on CI runners.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ci-package-smoke.py"
COMPARE = Path(__file__).resolve().parents[2] / "scripts" / "ci-direct-vs-proxy.py"
SOFTHSM_WIN_SHA256 = (
    "85273BCC1A6B90E877F7BB4F7E90221D57103D8F5241D154A79DD730A135B910"
)


def load_script():
    module_name = "ci_package_smoke_under_test"
    spec = importlib.util.spec_from_file_location(module_name, SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load ci-package-smoke.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def load_compare():
    module_name = "ci_compare_for_smoke_test"
    spec = importlib.util.spec_from_file_location(module_name, COMPARE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


mod = load_script()


class ExplicitPathTests(unittest.TestCase):
    def test_no_workspace_fallback_in_source(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("target/release", text)
        self.assertNotIn("target\\\\release", text)

    def test_bundle_is_required(self):
        with self.assertRaises(SystemExit) as ctx:
            mod.parse_args(["linux-bundle"])
        self.assertNotEqual(ctx.exception.code, 0)

    def test_apk_dir_is_required(self):
        with self.assertRaises(SystemExit) as ctx:
            mod.parse_args(["apk-verify"])
        self.assertNotEqual(ctx.exception.code, 0)

    def test_windows_bundle_is_required(self):
        with self.assertRaises(SystemExit) as ctx:
            mod.parse_args(["windows-bundle"])
        self.assertNotEqual(ctx.exception.code, 0)

    def test_missing_binary_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "no-such-daemon")
            with self.assertRaises(SystemExit):
                mod.require_executable(missing, "daemon")
            with self.assertRaises(SystemExit):
                mod.require_file(missing, "shim")


class BundleVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def make_bundle(self, tamper=False):
        bindir = self.root / "bundle" / "bin"
        bindir.mkdir(parents=True)
        daemon = bindir / "pkcs11-proxy-ng"
        daemon.write_bytes(b"daemon-bytes")
        digest = hashlib.sha256(b"daemon-bytes").hexdigest()
        if tamper:
            daemon.write_bytes(b"tampered-bytes")
        notices = self.root / "bundle" / "THIRD_PARTY_NOTICES"
        notices.write_text("notices")
        provenance = {
            "format_version": 1,
            "target": "x86_64-unknown-linux-gnu",
            "source_mode": "archive",
            "artifacts": [
                {"name": "pkcs11-proxy-ng", "sha256": digest, "size": 12,
                 "package": "pkcs11-proxy-ng", "kind": "bin"},
            ],
        }
        prov_path = self.root / "bundle" / "build-provenance.json"
        prov_path.write_text(json.dumps(provenance))
        return self.root / "bundle", prov_path

    def test_matching_bundle_verifies(self):
        bundle, provenance = self.make_bundle()
        result = mod.verify_prepared_bundle(bundle, provenance)
        self.assertEqual(result["binaries"], ["pkcs11-proxy-ng"])

    def test_tampered_binary_refused(self):
        bundle, provenance = self.make_bundle(tamper=True)
        with self.assertRaises(SystemExit):
            mod.verify_prepared_bundle(bundle, provenance)

    def test_missing_notices_refused(self):
        bundle, provenance = self.make_bundle()
        (bundle / "THIRD_PARTY_NOTICES").unlink()
        with self.assertRaises(SystemExit):
            mod.verify_prepared_bundle(bundle, provenance)

    def test_missing_provenance_refused(self):
        bundle, provenance = self.make_bundle()
        provenance.unlink()
        with self.assertRaises(SystemExit):
            mod.verify_prepared_bundle(bundle, provenance)


class ProviderOperationTests(unittest.TestCase):
    def test_operation_chain_names_session_login_keygen_sign(self):
        chain = mod.provider_operation_chain()
        for marker in ("C_OpenSession", "C_Login", "C_GenerateKey", "C_Sign"):
            with self.subTest(marker=marker):
                self.assertIn(marker, chain)

    def test_failing_provider_command_propagates(self):
        with mock.patch.object(mod.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=1, stdout="", stderr="CKR_DEVICE_ERROR")
            with self.assertRaises(SystemExit) as ctx:
                mod.run_provider_step(["pkcs11-tool", "--sign"], "sign")
            self.assertNotEqual(ctx.exception.code, 0)

    def test_daemon_log_retained_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "daemon.log")
            with open(log, "w") as fh:
                fh.write("startup failed\n")
            with mock.patch.object(mod, "wait_for_daemon", return_value=False):
                with self.assertRaises(SystemExit):
                    mod.require_daemon_ready(log, port=1, proc=mock.Mock())
            self.assertTrue(os.path.isfile(log))
            self.assertIn("startup failed", open(log).read())


class WindowsProvisioningTests(unittest.TestCase):
    def test_pinned_sha_matches_brief_verbatim(self):
        self.assertEqual(mod.SOFTHSM_WIN_SHA256, SOFTHSM_WIN_SHA256)

    def test_pinned_sha_matches_compare_helper(self):
        compare = load_compare()
        self.assertEqual(mod.SOFTHSM_WIN_SHA256, compare.SOFTHSM_WIN_SHA256)

    def test_hash_mismatch_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            zpath = os.path.join(tmp, "softhsm2.zip")
            with zipfile.ZipFile(zpath, "w") as zf:
                zf.writestr("SoftHSM2/lib/x.dll", b"fake")
            with self.assertRaises(SystemExit):
                mod.verify_softhsm_zip(zpath)

    def test_cross_width_smoke_requires_live_daemon(self):
        # The DLL check is not standalone: it needs an endpoint plus a
        # configured token, and a failing run must fail the smoke.
        with mock.patch.object(mod.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=3, stdout="", stderr="no daemon")
            with self.assertRaises(SystemExit):
                mod.run_cross_width_smoke("cross_width_smoke.exe", "shim.dll",
                                          "http://127.0.0.1:9")


class ZipSafetyTests(unittest.TestCase):
    def test_dotdot_member_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            zpath = os.path.join(tmp, "evil.zip")
            with zipfile.ZipFile(zpath, "w") as zf:
                zf.writestr("../evil.txt", b"pwn")
            dest = os.path.join(tmp, "out")
            os.makedirs(dest)
            with self.assertRaises(SystemExit):
                mod.safe_extract_zip(zpath, dest)
            self.assertFalse(os.path.exists(os.path.join(tmp, "evil.txt")))


class ApkSetTests(unittest.TestCase):
    LICENSED_MEMBERS = (
        "usr/share/licenses/{pkg}/LICENSE-APACHE",
        "usr/share/licenses/{pkg}/LICENSE-MIT",
        "usr/share/licenses/{pkg}/THIRD_PARTY_NOTICES",
        "usr/share/licenses/{pkg}/notice-inventory.json",
        "usr/share/licenses/{pkg}/build-provenance.json",
        "usr/share/licenses/{pkg}/license-material/ring-0.17.14/licenses/LICENSE",
        "usr/share/licenses/{pkg}/license-material/rust-std/COPYRIGHT-library.html",
    )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.apk_dir = Path(self.temp.name) / "apk" / "x86_64"
        self.apk_dir.mkdir(parents=True)

    def make_apk(self, package, members, release="0.2.0-r0"):
        import io
        import tarfile

        path = self.apk_dir / f"{package}-{release}.apk"
        with tarfile.open(path, "w:gz") as archive:
            for member in members:
                data = b"material"
                info = tarfile.TarInfo(member)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return path

    def test_matching_set_verifies(self):
        for package in mod.APK_PACKAGES:
            if package == "pkcs11-proxy-ng-compat":
                self.make_apk(package, [".PKGINFO"])
            else:
                self.make_apk(package, [m.format(pkg=package) for m in self.LICENSED_MEMBERS])
        hits = mod.verify_apk_set(str(self.apk_dir.parent))
        self.assertEqual(set(hits), set(mod.APK_PACKAGES))

    def test_missing_member_refused(self):
        members = [m.format(pkg="pkcs11-proxy-ng-shim") for m in self.LICENSED_MEMBERS]
        members = [m for m in members if not m.endswith("THIRD_PARTY_NOTICES")]
        self.make_apk("pkcs11-proxy-ng-shim", members)
        for package in ("pkcs11-proxy-ng-daemon", "pkcs11-proxy-ng-cli"):
            self.make_apk(package, [m.format(pkg=package) for m in self.LICENSED_MEMBERS])
        self.make_apk("pkcs11-proxy-ng-compat", [".PKGINFO"])
        with self.assertRaises(SystemExit):
            mod.verify_apk_set(str(self.apk_dir.parent))

    def test_missing_package_refused(self):
        self.make_apk("pkcs11-proxy-ng-shim",
                      [m.format(pkg="pkcs11-proxy-ng-shim") for m in self.LICENSED_MEMBERS])
        with self.assertRaises(SystemExit):
            mod.verify_apk_set(str(self.apk_dir.parent))

    def test_ambiguous_package_refused(self):
        members = [m.format(pkg="pkcs11-proxy-ng-shim") for m in self.LICENSED_MEMBERS]
        self.make_apk("pkcs11-proxy-ng-shim", members, release="0.2.0-r0")
        self.make_apk("pkcs11-proxy-ng-shim", members, release="0.2.0-r1")
        with self.assertRaises(SystemExit):
            mod.verify_apk_set(str(self.apk_dir.parent))


class TarballTests(unittest.TestCase):
    def test_round_trip_and_find_staged(self):
        import io
        import tarfile

        with tempfile.TemporaryDirectory() as tmp:
            tarball = os.path.join(tmp, "bundle.tar.gz")
            with tarfile.open(tarball, "w:gz") as archive:
                data = b"daemon-bytes"
                info = tarfile.TarInfo("name/bin/pkcs11-proxy-ng")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            dest = os.path.join(tmp, "out")
            mod.safe_extract_tarball(tarball, dest)
            self.assertEqual(mod.find_staged(dest, "pkcs11-proxy-ng"),
                             os.path.join(dest, "name", "bin", "pkcs11-proxy-ng"))

    def test_dotdot_member_refused(self):
        import io
        import tarfile

        with tempfile.TemporaryDirectory() as tmp:
            tarball = os.path.join(tmp, "evil.tar.gz")
            with tarfile.open(tarball, "w:gz") as archive:
                data = b"pwn"
                info = tarfile.TarInfo("../evil.txt")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            with self.assertRaises(SystemExit):
                mod.safe_extract_tarball(tarball, os.path.join(tmp, "out"))
            self.assertFalse(os.path.exists(os.path.join(tmp, "evil.txt")))


if __name__ == "__main__":
    unittest.main()

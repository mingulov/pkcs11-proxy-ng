"""Unit tests for scripts/ci-package-smoke.py (Stage B, Task 5a).

The smoke contract is reusable: the same entry points verify
archive-built bundles in CI today and registry release bundles before
GitHub asset publication later. Provider-dependent paths (real SoftHSM
token, daemon start, pkcs11-tool / cross_width_smoke execution) are
exercised through mocks here and at runtime on CI runners.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
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

    def test_macos_bundle_is_required(self):
        with self.assertRaises(SystemExit) as ctx:
            mod.parse_args(["macos-bundle"])
        self.assertNotEqual(ctx.exception.code, 0)

    def test_macos_bundle_accepts_exact_paths(self):
        args = mod.parse_args(["macos-bundle", "--bundle", "b", "--workdir", "w"])
        self.assertEqual((args.bundle, args.workdir), ("b", "w"))

    def test_installed_verify_needs_expected_hashes(self):
        with self.assertRaises(SystemExit) as ctx:
            mod.parse_args(["installed-verify", "--daemon", "d",
                            "--shim", "s", "--cli", "c"])
        self.assertNotEqual(ctx.exception.code, 0)

    def test_slot_option_removed(self):
        # The smokes address the scratch token by label, never by slot
        # number; --slot was dead CLI surface and must stay rejected.
        cases = [
            ["linux-bundle", "--bundle", "b", "--workdir", "w", "--slot", "1"],
            ["windows-bundle", "--bundle", "b", "--workdir", "w", "--slot", "1"],
            ["macos-bundle", "--bundle", "b", "--workdir", "w", "--slot", "1"],
            ["installed-smoke", "--daemon", "d", "--shim", "s", "--cli", "c",
             "--workdir", "w", "--slot", "1"],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                with self.assertRaises(SystemExit) as ctx:
                    mod.parse_args(argv)
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


class DaemonStartupCleanupTests(unittest.TestCase):
    def test_readiness_timeout_stops_owned_daemon(self):
        # A slow or stuck provider must not survive a failed smoke:
        # the startup helper owns the process until it is bound, so
        # it must terminate it when readiness times out — including
        # on the restart path, which uses the same helper.
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "daemon.log")
            proc = mock.Mock()
            with mock.patch.object(mod.subprocess, "Popen",
                                   return_value=proc), \
                 mock.patch.object(mod, "wait_for_daemon", return_value=False):
                with self.assertRaises(SystemExit) as ctx:
                    mod.start_smoke_daemon("daemon", "proxy.toml", log, 1)
            self.assertIn("did not bind", str(ctx.exception.code),
                          "the original readiness diagnostic must survive cleanup")
            proc.terminate.assert_called_once_with()

    def test_stop_waits_after_forced_termination(self):
        # After SIGKILL the handle must be reaped before any restart,
        # or the old daemon can still hold the port/socket.
        proc = mock.Mock()
        proc.wait.side_effect = [subprocess.TimeoutExpired("daemon", 30), None]
        mod.stop_smoke_daemon(proc)
        proc.terminate.assert_called_once_with()
        proc.kill.assert_called_once_with()
        self.assertEqual(proc.wait.call_count, 2,
                         "stop must wait again after killing")


class DaemonLogAssertionTests(unittest.TestCase):
    def test_slow_appearing_lines_pass(self):
        # Fix round 3: the readiness gate passes on socket-bind, which
        # precedes the async tracing flush — a writer thread stands in
        # for the late flush. The assertion must poll, not read once:
        # the needles are VERIFIED absent at call time, so a single
        # immediate read would fail this test deterministically.
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "daemon.log")
            Path(log).write_text("starting up\n", encoding="utf-8")
            pre = Path(log).read_text(encoding="utf-8")
            self.assertNotIn(mod.DAEMON_LOG_TCP, pre)
            self.assertNotIn(mod.DAEMON_LOG_REGISTRY, pre)

            def late_flush():
                time.sleep(0.3)
                with open(log, "a", encoding="utf-8") as handle:
                    handle.write(f"{mod.DAEMON_LOG_REGISTRY} for 42 mechanisms\n"
                                 "listening on tcp addr=127.0.0.1:1 auth=Mtls\n"
                                 "listening on unix socket path=/tmp/x.sock\n")

            writer = threading.Thread(target=late_flush, daemon=True)
            writer.start()
            try:
                mod.assert_daemon_logs(log, mtls=True, uds=True)
            finally:
                writer.join(timeout=10)
            self.assertFalse(writer.is_alive(), "writer thread must finish")

    def test_genuinely_missing_line_fails_closed(self):
        # Polling must not weaken the gate: a line that never arrives
        # still fails loudly after the deadline, with the exact
        # historical message.
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "daemon.log")
            Path(log).write_text(f"{mod.DAEMON_LOG_REGISTRY} for 42 mechanisms\n",
                                 encoding="utf-8")
            with self.assertRaises(SystemExit) as ctx:
                mod.assert_daemon_logs(log, mtls=True, uds=False, timeout_s=0.2)
            self.assertEqual(str(ctx.exception.code),
                             f"daemon log missing {mod.DAEMON_LOG_TCP!r}; see {log}")

    def test_plaintext_warn_still_required(self):
        # Plaintext posture without its loud warning keeps the exact
        # historical message (polled, then fail-closed).
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "daemon.log")
            Path(log).write_text(f"{mod.DAEMON_LOG_REGISTRY} for 42 mechanisms\n"
                                 "listening on tcp addr=127.0.0.1:1 auth=None\n",
                                 encoding="utf-8")
            with self.assertRaises(SystemExit) as ctx:
                mod.assert_daemon_logs(log, mtls=False, uds=False, timeout_s=0.2)
            self.assertEqual(str(ctx.exception.code),
                             f"plaintext daemon hid its loud warning; see {log}")

    def test_mtls_warn_rejected(self):
        # mTLS posture that logged the plaintext warning is still a
        # loud failure with the exact historical message.
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "daemon.log")
            Path(log).write_text(f"{mod.DAEMON_LOG_REGISTRY} for 42 mechanisms\n"
                                 "listening on tcp addr=127.0.0.1:1 auth=Mtls\n"
                                 f"{mod.DAEMON_LOG_TCP_WARN} oops\n",
                                 encoding="utf-8")
            with self.assertRaises(SystemExit) as ctx:
                mod.assert_daemon_logs(log, mtls=True, uds=False)
            self.assertEqual(str(ctx.exception.code),
                             f"mTLS daemon logged plaintext mode; see {log}")


class WindowsProvisioningTests(unittest.TestCase):
    def test_pinned_sha_matches_brief_verbatim(self):
        self.assertEqual(mod.SOFTHSM_WIN_SHA256, SOFTHSM_WIN_SHA256)

    def test_pinned_sha_matches_compare_helper(self):
        compare = load_compare()
        self.assertEqual(mod.SOFTHSM_WIN_SHA256, compare.SOFTHSM_WIN_SHA256)

    def test_no_duplicate_softhsm_verifier(self):
        # Single enforcement point: provision_softhsm_windows in the
        # compare helper. This module must not grow its own verifier.
        self.assertFalse(hasattr(mod, "verify_softhsm_zip"))
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("def verify_softhsm_zip", source)
        self.assertIn("provision_softhsm_windows", source)

    def test_hash_mismatch_refused_by_enforcement_point(self):
        compare = load_compare()
        with tempfile.TemporaryDirectory() as tmp:
            def fake_download(url, dest):
                Path(dest).write_bytes(b"not-the-pinned-zip")
            with mock.patch.object(compare, "download_file",
                                   side_effect=fake_download):
                with self.assertRaises(SystemExit):
                    compare.provision_softhsm_windows(tmp)

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

    PAYLOAD_FIXTURES = {
        "pkcs11-proxy-ng-shim": ("usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so",
                                 b"shim-payload-bytes"),
        "pkcs11-proxy-ng-daemon": ("usr/bin/pkcs11-proxy-ng",
                                   b"daemon-payload-bytes"),
        "pkcs11-proxy-ng-cli": ("usr/bin/pkcs11-proxy-ng-cli",
                                b"cli-payload-bytes"),
    }

    def make_apk(self, package, members, release="0.2.0-r0", contents=None):
        import io
        import tarfile

        contents = contents or {}
        path = self.apk_dir / f"{package}-{release}.apk"
        with tarfile.open(path, "w:gz") as archive:
            for member in members:
                data = contents.get(member, b"material")
                info = tarfile.TarInfo(member)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return path

    def make_full_set(self):
        for package in mod.APK_PACKAGES:
            if package == "pkcs11-proxy-ng-compat":
                self.make_apk(package, [".PKGINFO"])
                continue
            member, payload = self.PAYLOAD_FIXTURES[package]
            members = [m.format(pkg=package) for m in self.LICENSED_MEMBERS]
            members.append(member)
            self.make_apk(package, members, contents={member: payload})

    def make_installed(self, tamper_role=None):
        installed = {}
        for package, (member, payload) in self.PAYLOAD_FIXTURES.items():
            role = {"pkcs11-proxy-ng-shim": "shim",
                    "pkcs11-proxy-ng-daemon": "daemon",
                    "pkcs11-proxy-ng-cli": "cli"}[package]
            path = Path(self.temp.name) / f"installed-{role}"
            data = b"tampered-installed-bytes" if role == tamper_role else payload
            path.write_bytes(data)
            if role in ("daemon", "cli"):
                os.chmod(path, 0o755)
            installed[role] = str(path)
        return installed

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

    def test_payload_hashes_recorded_from_apk_bytes(self):
        self.make_full_set()
        reference = Path(self.temp.name) / "payload-hashes.json"
        mod.verify_apk_set(str(self.apk_dir.parent), hash_output=str(reference))
        recorded = json.loads(reference.read_text(encoding="utf-8"))["binaries"]
        self.assertEqual(set(recorded), {"daemon", "shim", "cli"})
        for package, (member, payload) in self.PAYLOAD_FIXTURES.items():
            role = {"pkcs11-proxy-ng-shim": "shim",
                    "pkcs11-proxy-ng-daemon": "daemon",
                    "pkcs11-proxy-ng-cli": "cli"}[package]
            with self.subTest(role=role):
                self.assertEqual(recorded[role]["package"], package)
                self.assertEqual(recorded[role]["member"], member)
                self.assertEqual(recorded[role]["sha256"],
                                 hashlib.sha256(payload).hexdigest())

    def test_installed_hashes_match_pass(self):
        self.make_full_set()
        reference = Path(self.temp.name) / "payload-hashes.json"
        mod.verify_apk_set(str(self.apk_dir.parent), hash_output=str(reference))
        installed = self.make_installed()
        record = Path(self.temp.name) / "installed-hashes.json"
        checked = mod.verify_installed_hashes(
            installed["daemon"], installed["shim"], installed["cli"],
            str(reference), record_path=str(record))
        self.assertEqual(set(checked), {"daemon", "shim", "cli"})
        evidence = json.loads(record.read_text(encoding="utf-8"))["binaries"]
        for role, payload in (("daemon", b"daemon-payload-bytes"),
                              ("shim", b"shim-payload-bytes"),
                              ("cli", b"cli-payload-bytes")):
            with self.subTest(role=role):
                self.assertEqual(evidence[role]["sha256"],
                                 hashlib.sha256(payload).hexdigest())
                self.assertEqual(evidence[role]["path"], installed[role])

    def test_tampered_installed_binary_refused(self):
        self.make_full_set()
        reference = Path(self.temp.name) / "payload-hashes.json"
        mod.verify_apk_set(str(self.apk_dir.parent), hash_output=str(reference))
        for role in ("daemon", "shim", "cli"):
            with self.subTest(role=role):
                installed = self.make_installed(tamper_role=role)
                with self.assertRaises(SystemExit):
                    mod.verify_installed_hashes(
                        installed["daemon"], installed["shim"], installed["cli"],
                        str(reference))

    def test_missing_payload_member_refused(self):
        # License-only APKs verify without a reference, but recording
        # payload hashes must refuse a set whose binaries are absent.
        for package in mod.APK_PACKAGES:
            if package == "pkcs11-proxy-ng-compat":
                self.make_apk(package, [".PKGINFO"])
            else:
                self.make_apk(package, [m.format(pkg=package) for m in self.LICENSED_MEMBERS])
        reference = Path(self.temp.name) / "payload-hashes.json"
        with self.assertRaises(SystemExit):
            mod.verify_apk_set(str(self.apk_dir.parent), hash_output=str(reference))

    def test_missing_reference_role_refused(self):
        self.make_full_set()
        reference = Path(self.temp.name) / "payload-hashes.json"
        mod.verify_apk_set(str(self.apk_dir.parent), hash_output=str(reference))
        trimmed = json.loads(reference.read_text(encoding="utf-8"))
        del trimmed["binaries"]["cli"]
        reference.write_text(json.dumps(trimmed))
        installed = self.make_installed()
        with self.assertRaises(SystemExit):
            mod.verify_installed_hashes(
                installed["daemon"], installed["shim"], installed["cli"],
                str(reference))


class TemplateRenderTests(unittest.TestCase):
    TEMPLATE = """\
[backend]
module = "/CHANGE_ME/path/to/backend.so"

[proxy]
max_contexts = 1
request_timeout_secs = 60

[listener.remote]
bind = "127.0.0.1:7512"
auth = "mtls"
ca_cert = "/CHANGE_ME/tls/ca.crt"
server_cert = "/CHANGE_ME/tls/server.crt"
server_key = "/CHANGE_ME/tls/server.key"

[listener.local]
path = "/CHANGE_ME/proxy.sock"
auth = "peer_cred"

[auth]
allow_all_authenticated = true
"""

    def test_render_substitutes_named_values_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            template = os.path.join(tmp, "proxy.toml")
            output = os.path.join(tmp, "rendered.toml")
            Path(template).write_text(self.TEMPLATE)
            mod.render_template(template, output, module="/real/backend.so", port=44999,
                                ca_cert="/tls/ca.crt", server_cert="/tls/server.crt",
                                server_key="/tls/server.key",
                                socket_path="/run/proxy.sock")
            rendered = Path(output).read_text(encoding="utf-8")
            self.assertIn('module = "/real/backend.so"', rendered)
            self.assertIn('bind = "127.0.0.1:44999"', rendered)
            self.assertIn('ca_cert = "/tls/ca.crt"', rendered)
            self.assertIn('server_cert = "/tls/server.crt"', rendered)
            self.assertIn('server_key = "/tls/server.key"', rendered)
            self.assertIn('path = "/run/proxy.sock"', rendered)
            # The shipped posture survives rendering untouched.
            for needle in ('auth = "mtls"', "max_contexts = 1",
                           'auth = "peer_cred"', "allow_all_authenticated = true"):
                self.assertIn(needle, rendered)
            self.assertNotIn("CHANGE_ME", rendered)

    def test_render_escapes_windows_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            template = os.path.join(tmp, "proxy.toml")
            output = os.path.join(tmp, "rendered.toml")
            Path(template).write_text(self.TEMPLATE)
            mod.render_template(template, output,
                                module="C:\\Vendor\\backend.dll", port=7512,
                                ca_cert="C:\\TLS\\ca.pem", server_cert="C:\\TLS\\srv.pem",
                                server_key="C:\\TLS\\key.pem")
            rendered = Path(output).read_text(encoding="utf-8")
            self.assertIn('module = "C:\\\\Vendor\\\\backend.dll"', rendered)
            self.assertIn('ca_cert = "C:\\\\TLS\\\\ca.pem"', rendered)

    def test_render_refuses_missing_named_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            template = os.path.join(tmp, "proxy.toml")
            output = os.path.join(tmp, "rendered.toml")
            Path(template).write_text("[backend]\nmodule = \"/x.so\"\n")
            with self.assertRaises(SystemExit):
                mod.render_template(template, output, module="/real.so", port=1,
                                    ca_cert="/ca", server_cert="/srv", server_key="/key")

    def test_no_hand_rolled_daemon_config(self):
        # The smoke renders shipped templates; it must not write its
        # own undocumented plaintext configuration anymore.
        self.assertFalse(hasattr(mod, "write_daemon_config"),
                         "hand-rolled write_daemon_config must be removed")
        self.assertNotIn("allow_insecure_tcp = true",
                         SCRIPT.read_text(encoding="utf-8"))


class BundleTemplateDiscoveryTests(unittest.TestCase):
    def test_finds_shipped_bundle_template(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "extracted" / "name"
            for tier in ("prod", "staging", "bundle"):
                target = root / "examples/configs" / tier / "proxy.toml"
                target.parent.mkdir(parents=True)
                target.write_text(f"# {tier}\n")
            found = mod.find_bundle_template(str(Path(tmp) / "extracted"))
            self.assertEqual(found, str(root / "examples/configs/bundle/proxy.toml"))

    def test_missing_or_ambiguous_template_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                mod.find_bundle_template(tmp)
            first = Path(tmp) / "a/examples/configs/bundle/proxy.toml"
            second = Path(tmp) / "b/examples/configs/bundle/proxy.toml"
            for target in (first, second):
                target.parent.mkdir(parents=True)
                target.write_text("# bundle\n")
            with self.assertRaises(SystemExit):
                mod.find_bundle_template(tmp)


class SmokeWiringTests(unittest.TestCase):
    def test_bundle_lanes_pass_shipped_template(self):
        for command, shim_name in (("linux-bundle", "libpkcs11_proxy_ng_shim.so"),
                                   ("macos-bundle", "libpkcs11_proxy_ng_shim.dylib")):
            with self.subTest(command=command):
                args = mod.parse_args([command, "--bundle", "b", "--workdir", "w"])
                with tempfile.TemporaryDirectory() as tmp:
                    template = os.path.join(tmp, "proxy.toml")
                    Path(template).write_text("# bundle\n")
                    with mock.patch.object(mod, "require_file",
                                           side_effect=lambda p, _l: p), \
                         mock.patch.object(mod, "require_dir",
                                           side_effect=lambda p, _l: p), \
                         mock.patch.object(mod, "safe_extract_tarball"), \
                         mock.patch.object(Path, "rglob",
                                           return_value=[Path("x/build-provenance.json")]), \
                         mock.patch.object(mod, "verify_prepared_bundle"), \
                         mock.patch.object(mod, "find_bundle_template",
                                           return_value=template), \
                         mock.patch.object(mod, "find_staged",
                                           side_effect=["d", "c", shim_name]), \
                         mock.patch.object(mod, "unix_provider_smoke",
                                           return_value={}) as smoke:
                        if command == "linux-bundle":
                            mod.cmd_linux_bundle(args)
                        else:
                            with mock.patch.object(mod.sys, "platform", "linux"):
                                mod.cmd_macos_bundle(args)
                    _, kwargs = smoke.call_args
                    self.assertEqual(kwargs.get("template"), template)

    def test_installed_smoke_requires_template(self):
        with self.assertRaises(SystemExit) as ctx:
            mod.parse_args(["installed-smoke", "--daemon", "d", "--shim", "s",
                            "--cli", "c", "--workdir", "w"])
        self.assertNotEqual(ctx.exception.code, 0)
        args = mod.parse_args(["installed-smoke", "--daemon", "d", "--shim", "s",
                               "--cli", "c", "--workdir", "w", "--template", "t"])
        with mock.patch.object(mod, "unix_provider_smoke", return_value={}) as smoke:
            mod.cmd_installed_smoke(args)
        _, kwargs = smoke.call_args
        self.assertEqual(kwargs.get("template"), "t")

    def test_windows_lane_passes_shipped_template(self):
        args = mod.parse_args(["windows-bundle", "--bundle", "b", "--workdir", "w"])
        with mock.patch.object(mod, "require_file",
                               side_effect=lambda p, _l: p), \
             mock.patch.object(mod, "require_dir",
                               side_effect=lambda p, _l: p), \
             mock.patch.object(mod.os, "makedirs"), \
             mock.patch.object(mod, "safe_extract_zip"), \
             mock.patch.object(mod, "verify_prepared_bundle"), \
             mock.patch.object(Path, "rglob",
                               return_value=[Path("x/build-provenance.json")]), \
             mock.patch.object(mod, "find_staged",
                               side_effect=["d", "c", "s", "x", "t"]), \
             mock.patch.object(mod, "windows_provider_smoke",
                               return_value={}) as smoke:
            mod.cmd_windows_bundle(args)
        _, kwargs = smoke.call_args
        self.assertEqual(kwargs.get("template"), "t")


class CertGenerationTests(unittest.TestCase):
    def test_openssl_certs_verify_against_ca(self):
        if mod.shutil.which("openssl") is None:
            self.skipTest("openssl unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            certs = mod.generate_mtls_certs(tmp)
            for role in ("ca_cert", "server_cert", "server_key",
                         "client_cert", "client_key"):
                with self.subTest(role=role):
                    self.assertTrue(os.path.isfile(certs[role]))
                    self.assertGreater(os.path.getsize(certs[role]), 0)
            if os.name == "posix":
                import stat
                for role in ("server_key", "client_key"):
                    mode = stat.S_IMODE(os.stat(certs[role]).st_mode)
                    self.assertEqual(mode, 0o600, role)
            server = subprocess.run(
                ["openssl", "verify", "-CAfile", certs["ca_cert"], certs["server_cert"]],
                capture_output=True, text=True)
            self.assertEqual(server.returncode, 0, server.stderr)
            client = subprocess.run(
                ["openssl", "verify", "-CAfile", certs["ca_cert"], certs["client_cert"]],
                capture_output=True, text=True)
            self.assertEqual(client.returncode, 0, client.stderr)

    def test_server_cert_carries_localhost_san(self):
        # The smoke dials the daemon over localhost TLS: the server
        # certificate must carry the loopback SAN (this is what the
        # -extfile transfer in generate_mtls_certs is for).
        if mod.shutil.which("openssl") is None:
            self.skipTest("openssl unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            certs = mod.generate_mtls_certs(tmp)
            rendered = subprocess.run(
                ["openssl", "x509", "-in", certs["server_cert"],
                 "-noout", "-text"],
                capture_output=True, text=True)
            self.assertEqual(rendered.returncode, 0, rendered.stderr)
            self.assertIn("DNS:localhost", rendered.stdout)
            self.assertIn("127.0.0.1", rendered.stdout)

    def test_cert_generation_avoids_libressl_unsupported_flags(self):
        # Fix round 1 (F3): macOS LibreSSL rejects `x509
        # -copy_extensions` outright, so the smoke transfers the server
        # SAN via the portable -extfile/-extensions pair instead. Never
        # reintroduce the OpenSSL-only flag here.
        self.assertNotIn("copy_extensions", SCRIPT.read_text(encoding="utf-8"))

    def test_client_cert_is_version_3_end_entity(self):
        # Fix round 2: a bare `x509 -req` emits X.509 v3 on OpenSSL 3.x
        # but v1 on LibreSSL, and rustls refuses a v1 client identity
        # (UnsupportedCertVersion) before dialing. The minted client
        # certificate must therefore be v3 with an end-entity marker on
        # every minter.
        if mod.shutil.which("openssl") is None:
            self.skipTest("openssl unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            certs = mod.generate_mtls_certs(tmp)
            rendered = subprocess.run(
                ["openssl", "x509", "-in", certs["client_cert"],
                 "-noout", "-text"],
                capture_output=True, text=True)
            self.assertEqual(rendered.returncode, 0, rendered.stderr)
            self.assertIn("Version: 3", rendered.stdout)
            self.assertIn("CA:FALSE", rendered.stdout)

    def test_client_cert_wired_through_portable_extfile(self):
        # Fix round 2 guard: the client `x509 -req` must carry the same
        # portable -extfile/-extensions pair as the server call, so a
        # future edit cannot silently drop back to a bare (v1 on
        # LibreSSL) client certificate. Fails against the pre-fix
        # script, which names no client_cert section.
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"client.ext"', source)
        self.assertIn('"-extensions", "client_cert"', source)


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

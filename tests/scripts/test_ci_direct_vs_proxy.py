"""Unit tests for scripts/ci-direct-vs-proxy.py (Review-A M-1/M-2/m-6).

Covers the logic that is unit-testable without a provider: EXTRA-args
parsing, ZipSlip guard, download timeout wiring, token-provisioning
helpers, and differential argv construction (incl. the M-1 KAT-scope
decision). Provider-dependent paths -- softhsm2-util init, daemon start,
pkcs11-check runs, PyPI fetch, Windows disig URL/SHA -- are NOT unit
tested here; T2run proves them at runtime on first green dispatch.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ci-direct-vs-proxy.py"


def load_script():
    module_name = "ci_direct_vs_proxy_under_test"
    spec = importlib.util.spec_from_file_location(module_name, SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load ci-direct-vs-proxy.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


mod = load_script()


class ExtraArgsTests(unittest.TestCase):
    def test_unset_is_empty(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("EXTRA_P11CHECK_ARGS", None)
            self.assertEqual(mod.extra_p11check_args(), [])

    def test_blank_is_empty(self) -> None:
        with mock.patch.dict(os.environ, {"EXTRA_P11CHECK_ARGS": "   "}):
            self.assertEqual(mod.extra_p11check_args(), [])

    def test_simple_split(self) -> None:
        with mock.patch.dict(os.environ, {"EXTRA_P11CHECK_ARGS": "--skip-slow -k foo"}):
            self.assertEqual(mod.extra_p11check_args(), ["--skip-slow", "-k", "foo"])

    def test_quoted_args_survive(self) -> None:
        # m-6: str.split() mangled this into ['--marker', '"not', 'slow"', ...].
        with mock.patch.dict(os.environ, {"EXTRA_P11CHECK_ARGS": '--marker "not slow" -k foo'}):
            self.assertEqual(
                mod.extra_p11check_args(), ["--marker", "not slow", "-k", "foo"]
            )


class SafeExtractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def make_zip(self, members: dict[str, bytes]) -> Path:
        zpath = self.root / "test.zip"
        with zipfile.ZipFile(zpath, "w") as zf:
            for name, data in members.items():
                zf.writestr(name, data)
        return zpath

    def test_clean_zip_extracts(self) -> None:
        zpath = self.make_zip({"SoftHSM2/lib/x.dll": b"fake"})
        dest = self.root / "out"
        dest.mkdir()
        mod.safe_extractall(str(zpath), str(dest))
        self.assertEqual((dest / "SoftHSM2/lib/x.dll").read_bytes(), b"fake")

    def test_dotdot_member_refused(self) -> None:
        zpath = self.make_zip({"../evil.txt": b"pwn"})
        dest = self.root / "out"
        dest.mkdir()
        with self.assertRaises(SystemExit):
            mod.safe_extractall(str(zpath), str(dest))
        self.assertFalse((self.root / "evil.txt").exists())

    def test_absolute_member_refused(self) -> None:
        zpath = self.make_zip({"/tmp/ci-compare-abs-evil.txt": b"pwn"})
        dest = self.root / "out"
        dest.mkdir()
        with self.assertRaises(SystemExit):
            mod.safe_extractall(str(zpath), str(dest))
        self.assertFalse(Path("/tmp/ci-compare-abs-evil.txt").exists())


class DownloadTests(unittest.TestCase):
    def test_timeout_passed_to_urlopen(self) -> None:
        # m-6: urlretrieve() has no timeout parameter at all; the helper
        # must go through urlopen(url, timeout=...).
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "f.bin")
            body = mock.MagicMock()
            body.__enter__.return_value = body
            body.read.side_effect = [b"ab", b""]
            with mock.patch.object(mod.urllib.request, "urlopen", return_value=body) as uo:
                mod.download_file("https://example.invalid/x", dest, timeout_s=7)
            uo.assert_called_once_with("https://example.invalid/x", timeout=7)
            with open(dest, "rb") as f:
                self.assertEqual(f.read(), b"ab")

    def test_default_timeout_is_positive(self) -> None:
        self.assertGreater(mod.DOWNLOAD_TIMEOUT_S, 0)


class TokenProvisioningTests(unittest.TestCase):
    def test_init_argv_pins_and_label(self) -> None:
        argv = mod.init_token_argv("/usr/bin/softhsm2-util")
        self.assertEqual(argv[0], "/usr/bin/softhsm2-util")
        self.assertIn("--init-token", argv)
        self.assertIn("--free", argv)
        for flag, value in (
            ("--label", mod.TOKEN_LABEL),
            ("--so-pin", mod.SO_PIN),
            ("--pin", mod.USER_PIN),
        ):
            self.assertIn(flag, argv)
            self.assertEqual(argv[argv.index(flag) + 1], value)

    def test_init_argv_identical_across_phases(self) -> None:
        # M-2: identical provisioning holds by construction -- both phases
        # call this one helper, so the argv cannot drift.
        self.assertEqual(
            mod.init_token_argv("u"), mod.init_token_argv("u")
        )

    def test_init_failure_is_fail_loud(self) -> None:
        with mock.patch.object(mod, "run") as run:
            run.return_value = types.SimpleNamespace(returncode=3)
            with self.assertRaises(SystemExit):
                mod.init_scratch_token("softhsm2-util")
            run.assert_called_once_with(mod.init_token_argv("softhsm2-util"))

    def test_reset_wipes_then_reinits_identically(self) -> None:
        # M-2: DIRECT-phase token-persistent objects must not leak into the
        # PROXIED phase; the reset wipes the dir and re-inits with the same
        # helper/params as the initial provisioning.
        with tempfile.TemporaryDirectory() as tmp:
            token_dir = os.path.join(tmp, "tokens")
            os.makedirs(token_dir)
            polluted = os.path.join(token_dir, "persistent-object.db")
            with open(polluted, "w") as f:
                f.write("direct-phase residue")
            with mock.patch.object(mod, "run") as run:
                run.return_value = types.SimpleNamespace(returncode=0)
                mod.reset_token_state(token_dir, "softhsm2-util")
            self.assertFalse(os.path.exists(polluted))
            self.assertTrue(os.path.isdir(token_dir))
            run.assert_called_once_with(mod.init_token_argv("softhsm2-util"))


class DifferentialArgvTests(unittest.TestCase):
    def test_argv_shape(self) -> None:
        argv = mod.differential_argv("/w/direct/report.jsonl", "/w/proxied/report.jsonl")
        self.assertEqual(
            argv,
            [
                "pkcs11-check",
                "differential",
                "direct=/w/direct/report.jsonl",
                "proxied=/w/proxied/report.jsonl",
            ],
        )

    def test_no_all_flag_m1_decision(self) -> None:
        # M-1 decision (b): KAT-default scope, honestly documented in the
        # script docstring + workflow comments. If --all is ever wired it
        # must come with a margin story + updated contract text; this test
        # forces that to be a deliberate change, not drift.
        argv = mod.differential_argv("d", "p")
        self.assertNotIn("--all", argv)


if __name__ == "__main__":
    unittest.main()

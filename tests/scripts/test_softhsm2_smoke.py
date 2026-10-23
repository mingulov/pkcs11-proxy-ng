"""Hermetic smoke-workflow contracts; these do not qualify a real provider.

Only the shell entrypoint is real here. External provider/crypto tools are
strict command fixtures, and the daemon is a real owned TCP-listening process.
"""

from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/test-softhsm2-smoke.sh"

# Fixtures reject wrong arguments and unsafe store access, rather than silently
# making every shell invocation succeed. No provider or crypto code is loaded.
TOOL_FIXTURE = r'''#!PYTHON
import json
import os
from pathlib import Path
import shutil
import sys
import time

root = Path(os.environ["SMOKE_FIXTURE_ROOT"])
scenario = os.environ["SMOKE_FIXTURE_SCENARIO"]
name = Path(sys.argv[0]).name
args = sys.argv[1:]

def record(step, **details):
    with (root / "events.jsonl").open("a") as handle:
        handle.write(json.dumps({"step": step, "pid": os.getpid(), **details}) + "\n")

def require(condition, message):
    if not condition:
        raise SystemExit("invalid smoke command: " + message)

def scratch(path):
    path = Path(path)
    require(path.is_relative_to(root / "scratch"), "path escaped scratch store")
    return path

def value(option):
    require(args.count(option) == 1, "missing/duplicate " + option)
    return args[args.index(option) + 1]

def token_access(direct):
    pid = int((root / "daemon.pid").read_text())
    exists = Path(f"/proc/{pid}").exists()
    require(not exists if direct else exists,
            "direct access before daemon retirement/reaping" if direct else "proxy daemon missing")
    conf = scratch(os.environ["SOFTHSM2_CONF"])
    require("directories.tokendir = " + str(conf.parent / "tokens") in conf.read_text(),
            "wrong scratch token store")

record("tool-start", tool=name, argv=args)
if name == "softhsm2-util":
    conf = scratch(os.environ["SOFTHSM2_CONF"])
    require(args == ["--init-token", "--free", "--label", "r1-smoke",
                     "--so-pin", "abcd", "--pin", "1234"], "token initialization argv")
    require((conf.parent / "tokens").is_dir(), "scratch token directory absent")
    record("init-token", conf=str(conf))
elif name == "pkcs11-tool":
    module = value("--module")
    direct = module == str(root / "backend.so")
    require(direct or module == str(root / "shim.so"), "wrong module override")
    token_access(direct)
    prefix = ["--module", module, "--token-label", "r1-smoke", "--login", "--pin", "1234"]
    if "--list-slots" in args:
        require(not direct and args == ["--module", module, "--list-slots"], "list argv")
        record("proxy-list")
        if scenario == "proxy-list-fail":
            raise SystemExit(41)
        print("Slot 0: token label r1-smoke")
    elif "--keypairgen" in args:
        require(not direct and args == prefix + ["--keypairgen", "--key-type", "rsa:2048",
                                                "--label", "r1-smoke-key", "--id", "01"], "keygen argv")
        record("proxy-keygen")
        if scenario == "proxy-keygen-fail":
            raise SystemExit(42)
        print("RSA-2048 key pair generated")
    elif "--sign" in args:
        data, output = scratch(value("--input-file")), scratch(value("--output-file"))
        require(args == prefix + ["--sign", "--mechanism", "SHA256-RSA-PKCS", "--input-file", str(data),
                                  "--output-file", str(output), "--id", "01"], "sign argv/key/mechanism")
        require(len(data.read_bytes()) == 256, "wrong message size")
        stage = "direct-sign" if direct else "proxy-sign"
        record(stage, input=str(data), output=str(output))
        if direct:
            require(data.read_bytes() == (root / "proxy-message.bin").read_bytes(), "message changed")
        else:
            (root / "proxy-message.bin").write_bytes(data.read_bytes())
        if scenario == stage + "-fail":
            print("fixture " + stage + " failed", file=sys.stderr)
            raise SystemExit(44 if direct else 43)
        if scenario == stage + "-timeout":
            time.sleep(60)
        signature = b"P" * 256
        if scenario == stage + "-empty":
            signature = b""
        elif scenario == stage + "-short":
            signature = b"P" * 255
        elif scenario == stage + "-oversized":
            signature = b"P" * 257
        elif scenario == stage + "-bad":
            signature = b"B" * 256
        elif scenario == "signature-mismatch" and direct:
            signature = b"D" * 256
        output.write_bytes(signature)
    elif "--read-object" in args:
        output = scratch(value("--output-file"))
        require(direct and args == prefix + ["--read-object", "--type", "pubkey", "--id", "01",
                                            "--output-file", str(output)], "public-key export argv")
        record("read-public-key")
        if scenario == "read-fail":
            raise SystemExit(45)
        output.write_bytes(b"" if scenario == "read-empty" else b"DER" * 100)
    else:
        require(False, "unexpected pkcs11-tool operation")
elif name == "openssl":
    if args[0] == "rsa":
        source, output = scratch(value("-in")), scratch(value("-out"))
        require(args == ["rsa", "-inform", "DER", "-outform", "PEM", "-in", str(source),
                         "-pubin", "-out", str(output)], "public-key conversion argv")
        require(source.read_bytes() == b"DER" * 100, "invalid exported key")
        record("convert-public-key")
        if scenario == "convert-fail":
            raise SystemExit(46)
        output.write_bytes(b"" if scenario == "convert-empty" else b"PEM" * 150)
    elif args[0] == "dgst":
        public, signature, data = scratch(value("-verify")), scratch(value("-signature")), scratch(args[-1])
        require(args == ["dgst", "-sha256", "-verify", str(public), "-signature", str(signature), str(data)],
                "independent SHA-256 verification argv")
        require(public.read_bytes() == b"PEM" * 150, "invalid public key")
        require(data.read_bytes() == (root / "proxy-message.bin").read_bytes(), "verification message changed")
        stage = "verify-direct" if signature.name == "direct-sig.bin" else "verify-proxy"
        require(signature.name in ("sig.bin", "direct-sig.bin"), "unexpected signature path")
        record(stage)
        allowed = (b"P" * 256, b"D" * 256) if scenario == "signature-mismatch" else (b"P" * 256,)
        if scenario == stage + "-fail" or signature.read_bytes() not in allowed:
            print("fixture signature verification failed", file=sys.stderr)
            raise SystemExit(47)
        print("Verified OK")
    else:
        require(False, "unexpected openssl operation")
elif name == "rm":
    require(len(args) == 2 and args[0] == "-rf", "cleanup argv")
    target = scratch(args[1])
    record("cleanup", path=str(target))
    if scenario == "cleanup-fail":
        raise SystemExit(48)
    shutil.rmtree(target)
else:
    require(False, "unexpected fixture tool")
'''

DAEMON_FIXTURE = r'''#!PYTHON
import json
import os
from pathlib import Path
import signal
import socket
import sys
import tomllib

root = Path(os.environ["SMOKE_FIXTURE_ROOT"])
scenario = os.environ["SMOKE_FIXTURE_SCENARIO"]
config = Path(sys.argv[1])
assert len(sys.argv) == 2 and config.is_relative_to(root / "scratch")
settings = tomllib.loads(config.read_text())
assert settings["backend"]["module"] == str(root / "backend.so")
assert settings["proxy"]["shutdown_grace_secs"] == 30, "production shutdown proof was shortened"
listener = settings["listener"]["remote"]
assert listener["auth"] == "none" and listener["allow_insecure_tcp"] is True
host, port = listener["bind"].rsplit(":", 1)
assert host == "127.0.0.1"
(root / "daemon.pid").write_text(str(os.getpid()))

def record(step):
    with (root / "events.jsonl").open("a") as handle:
        handle.write(json.dumps({"step": step, "pid": os.getpid()}) + "\n")

running = True
def stop(signum, frame):
    global running
    record("daemon-term")
    if scenario != "wedged-shutdown":
        running = False

signal.signal(signal.SIGTERM, stop)
record("daemon-start")
print("listening on tcp without authentication", flush=True)
print("mechanism registry ready", flush=True)
with socket.socket() as server:
    server.bind((host, int(port)))
    server.listen()
    server.settimeout(0.05)
    while running:
        try:
            connection, _ = server.accept()
            connection.close()
        except TimeoutError:
            pass
record("daemon-exit")
raise SystemExit(49 if scenario == "shutdown-exit-fail" else 0)
'''


class SoftHsmSmokeWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Own orphaned descendants even if a deliberately broken shell leaves
        # them behind. This is local to this test process and restored below.
        cls.libc = ctypes.CDLL(None, use_errno=True)
        original = ctypes.c_int()
        if cls.libc.prctl(37, ctypes.byref(original), 0, 0, 0):  # PR_GET_CHILD_SUBREAPER
            raise RuntimeError("cannot inspect child subreaper state")
        cls.original_subreaper = original.value
        if cls.libc.prctl(36, 1, 0, 0, 0):  # PR_SET_CHILD_SUBREAPER
            raise RuntimeError("cannot supervise smoke-fixture descendants")

    @classmethod
    def tearDownClass(cls):
        if cls.libc.prctl(36, cls.original_subreaper, 0, 0, 0):
            raise RuntimeError("cannot restore child subreaper state")

    @staticmethod
    def session_pids(session):
        result = set()
        for entry in Path("/proc").iterdir():
            if entry.name.isdecimal():
                try:
                    fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
                    if int(fields[3]) == session:
                        result.add(int(entry.name))
                except (FileNotFoundError, ProcessLookupError):
                    pass
        return result

    def run_fixture(self, scenario="success", *, missing=None, overrides=None):
        with tempfile.TemporaryDirectory(prefix="softhsm-smoke-workflow-") as temp:
            root = Path(temp)
            bindir = root / "bin"
            bindir.mkdir()
            (root / "scratch").mkdir()
            host_config = root / "host-softhsm2.conf"
            host_config.write_text("existing user token configuration\n")
            fixture = TOOL_FIXTURE.replace("#!PYTHON", "#!" + sys.executable)
            for name in ("softhsm2-util", "pkcs11-tool", "openssl", "rm"):
                if name != missing:
                    tool = bindir / name
                    tool.write_text(fixture)
                    tool.chmod(0o755)
            # A closed PATH ensures missing prerequisites cannot fall through
            # to host provider tools. Core shell utilities remain real.
            for name in ("dirname", "mktemp", "mkdir", "cat", "grep", "tail", "head",
                         "stat", "cmp", "timeout", "sleep", "seq", "python3"):
                if name != missing:
                    resolved = shutil.which(name)
                    self.assertIsNotNone(resolved, "required fixture utility absent: " + name)
                    (bindir / name).symlink_to(resolved)
            daemon = root / "daemon"
            daemon.write_text(DAEMON_FIXTURE.replace("#!PYTHON", "#!" + sys.executable))
            daemon.chmod(0o755)
            (root / "shim.so").write_bytes(b"fixture shim; never loaded")
            (root / "backend.so").write_bytes(b"fixture backend; never loaded")
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(("PKCS11_PROXY_", "SOFTHSM2_"))}
            env.update({"PATH": str(bindir), "TMPDIR": str(root / "scratch"),
                        "SOFTHSM2_CONF": str(host_config),
                        "SMOKE_FIXTURE_ROOT": str(root), "SMOKE_FIXTURE_SCENARIO": scenario,
                        "PKCS11_PROXY_NG_DAEMON_BIN": str(daemon),
                        "PKCS11_PROXY_NG_SHIM_LIB": str(root / "shim.so"),
                        "PKCS11_PROXY_BACKEND_MODULE": str(root / "backend.so"),
                        "PKCS11_PROXY_SMOKE_SHUTDOWN_SECS": "1",
                        "PKCS11_PROXY_SMOKE_COMMAND_SECS": "1"})
            env.update(overrides or {})
            start = time.monotonic()
            process = subprocess.Popen(["/bin/bash", str(SCRIPT)], cwd=root, env=env,
                                       text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True)
            timed_out = False
            try:
                try:
                    stdout, stderr = process.communicate(timeout=8)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    stdout, stderr = process.communicate(timeout=2)
            finally:
                # GNU timeout may give a tool its own process group. Session
                # identity still binds every fixture descendant to this run.
                owned = self.session_pids(process.pid)
                for pid in owned:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                deadline = time.monotonic() + 2
                while owned and time.monotonic() < deadline:
                    for pid in tuple(owned):
                        try:
                            waited, _ = os.waitpid(pid, os.WNOHANG)
                        except ChildProcessError:
                            waited = pid if not Path(f"/proc/{pid}").exists() else 0
                        if waited:
                            owned.remove(pid)
                    if owned:
                        time.sleep(0.01)
                self.assertFalse(owned, "fixture descendants were not reaped")
            elapsed = time.monotonic() - start
            self.assertFalse(timed_out, f"smoke exceeded 8s fixture bound:\n{stdout}\n{stderr}")
            events_path = root / "events.jsonl"
            events = [json.loads(line) for line in events_path.read_text().splitlines()] if events_path.exists() else []
            self.assertEqual(host_config.read_text(), "existing user token configuration\n")
            result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
            scratch_contents = list((root / "scratch").iterdir())
            if scenario != "cleanup-fail":
                self.assertEqual(scratch_contents, [], "scratch token/artifacts survived cleanup")
            return result, events, elapsed

    def assert_failed(self, result, diagnostic=None):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("PASSED", result.stdout)
        if diagnostic:
            self.assertIn(diagnostic, result.stderr)

    def test_success_verifies_both_signatures_after_daemon_retirement(self):
        # Missing direct verification, omitted key ID, changed input, live
        # direct access, or success before failed cleanup must break this flow.
        result, events, _ = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASSED", result.stdout)
        stages = [event["step"] for event in events if event["step"] != "tool-start"]
        self.assertEqual(stages, ["init-token", "daemon-start", "proxy-list", "proxy-keygen",
                                 "proxy-sign", "daemon-term", "daemon-exit", "direct-sign",
                                 "read-public-key", "convert-public-key", "verify-proxy",
                                 "verify-direct", "cleanup"])

    def test_proxy_command_failures_preserve_errors_and_stop_daemon(self):
        for scenario, status in (("proxy-list-fail", 41), ("proxy-keygen-fail", 42), ("proxy-sign-fail", 43)):
            with self.subTest(scenario=scenario):
                result, events, _ = self.run_fixture(scenario)
                self.assert_failed(result)
                self.assertEqual(result.returncode, status, result.stderr)
                stages = [event["step"] for event in events]
                self.assertIn("daemon-exit", stages)
                self.assertNotIn("direct-sign", stages)

    def test_direct_command_failure_cannot_pass(self):
        result, _, _ = self.run_fixture("direct-sign-fail")
        self.assert_failed(result, "fixture direct-sign failed")
        self.assertEqual(result.returncode, 44)

    def test_signatures_must_be_exactly_rsa_2048_size(self):
        for stage in ("proxy-sign", "direct-sign"):
            for kind in ("empty", "short", "oversized"):
                with self.subTest(stage=stage, kind=kind):
                    result, _, _ = self.run_fixture(stage + "-" + kind)
                    self.assert_failed(result, "256-byte RSA-2048 signature")

    def test_bad_signatures_fail_independent_verification(self):
        for stage in ("proxy-sign", "direct-sign"):
            with self.subTest(stage=stage):
                result, _, _ = self.run_fixture(stage + "-bad")
                self.assert_failed(result, "fixture signature verification failed")

    def test_verified_deterministic_signatures_must_match(self):
        result, events, _ = self.run_fixture("signature-mismatch")
        self.assert_failed(result, "signatures differ")
        self.assertIn("verify-direct", [event["step"] for event in events])

    def test_public_key_export_and_conversion_failures_cannot_pass(self):
        for scenario, status in (("read-fail", 45), ("convert-fail", 46)):
            with self.subTest(scenario=scenario):
                result, _, _ = self.run_fixture(scenario)
                self.assert_failed(result)
                self.assertEqual(result.returncode, status)

    def test_empty_public_key_artifacts_cannot_pass(self):
        for scenario in ("read-empty", "convert-empty"):
            with self.subTest(scenario=scenario):
                result, _, _ = self.run_fixture(scenario)
                self.assert_failed(result, "public key")

    def test_each_verification_command_must_succeed(self):
        for stage in ("verify-proxy", "verify-direct"):
            with self.subTest(stage=stage):
                result, _, _ = self.run_fixture(stage + "-fail")
                self.assert_failed(result, "fixture signature verification failed")
                self.assertEqual(result.returncode, 47)

    def test_required_tools_fail_before_creating_token_store(self):
        for name in ("softhsm2-util", "pkcs11-tool", "openssl", "python3", "timeout", "cmp"):
            with self.subTest(tool=name):
                result, events, _ = self.run_fixture(missing=name)
                self.assert_failed(result, "Required command not found: " + name)
                self.assertEqual(events, [])

    def test_wedged_daemon_is_killed_reaped_and_cannot_pass(self):
        result, events, elapsed = self.run_fixture("wedged-shutdown")
        self.assert_failed(result, "SIGKILL")
        self.assertLess(elapsed, 5)
        self.assertNotIn("direct-sign", [event["step"] for event in events])

    def test_failed_daemon_wait_status_cannot_pass(self):
        result, events, _ = self.run_fixture("shutdown-exit-fail")
        self.assert_failed(result, "status 49")
        self.assertNotIn("direct-sign", [event["step"] for event in events])

    def test_hung_provider_command_is_bounded_and_daemon_is_reaped(self):
        result, events, elapsed = self.run_fixture("proxy-sign-timeout")
        self.assert_failed(result, "status 124")
        self.assertEqual(result.returncode, 124)
        self.assertLess(elapsed, 5)
        self.assertIn("daemon-exit", [event["step"] for event in events])

    def test_cleanup_failure_cannot_print_success(self):
        result, _, _ = self.run_fixture("cleanup-fail")
        self.assert_failed(result, "cleanup")

    def test_invalid_budgets_fail_before_creating_token_store(self):
        for name in ("PKCS11_PROXY_SMOKE_SHUTDOWN_SECS", "PKCS11_PROXY_SMOKE_COMMAND_SECS"):
            for value in ("0", "31", "-1", "nan", "1.5", "999999999999999999999", ""):
                with self.subTest(name=name, value=value):
                    result, events, _ = self.run_fixture(overrides={name: value})
                    self.assert_failed(result, "integer from 1 to 30")
                    self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()

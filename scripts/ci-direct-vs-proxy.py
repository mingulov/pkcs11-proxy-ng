#!/usr/bin/env python3
"""Direct-vs-proxied transparency gate (cross-platform CI core).

Runs the SAME pkcs11-check suite (from PyPI) twice against a scratch
SoftHSM2 token -- once against the SoftHSM module directly, once through
the proxy shim + release daemon -- then compares the two reports with
``pkcs11-check differential``. Any divergence is a proxy bug: the shim
must be indistinguishable from the backend (AGENTS.md rule 2).

Flow mirrors scripts/test-softhsm2-smoke.sh, generalized to Linux/macOS/
Windows with stdlib only (no shell/PowerShell twin to keep in sync):

  1. provision SoftHSM2 (system install on unix; pinned disig portable
     zip, hash-verified, on Windows) and init a scratch token;
  2. write a loopback-only daemon config (auth="none", CI-only -- same
     insecure-TCP shape the smoke script asserts, never a default);
  3. run pkcs11-check DIRECT against SoftHSM;
  4. start the daemon, run pkcs11-check PROXIED against the shim;
  5. run ``pkcs11-check differential`` on the two report.jsonl files.

Gate (strict): direct exit 0 AND proxied exit 0 AND differential exit 0.
Extra pkcs11-check args (subset tuning) pass through EXTRA_P11CHECK_ARGS.

Usage (after ``cargo build --release``)::

    python3 scripts/ci-direct-vs-proxy.py [--release-dir target/release]
"""

import argparse
import hashlib
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

USER_PIN = "1234"
SO_PIN = "abcd"
TOKEN_LABEL = "ci-compare"

# Same pin the pkcs11-check win lanes use (win-ctr/setup.ps1).
SOFTHSM_WIN_URL = (
    "https://github.com/disig/SoftHSM2-for-Windows/releases/download/"
    "v2.5.0/SoftHSM2-2.5.0-portable.zip"
)
SOFTHSM_WIN_SHA256 = "85273BCC1A6B90E877F7BB4F7E90221D57103D8F5241D154A79DD730A135B910"

SOFTHSM_UNIX_LIB_CANDIDATES = [
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/opt/homebrew/lib/softhsm/libsofthsm2.dylib",
    "/usr/local/lib/softhsm/libsofthsm2.dylib",
]

DAEMON_LOG_TCP_WARN = "listening on tcp without authentication"
DAEMON_LOG_REGISTRY = "mechanism registry ready"


def log(msg):
    print(f"[ci-compare] {msg}", flush=True)


def run(cmd, env=None, cwd=None):
    merged = dict(os.environ)
    if env:
        merged.update(env)
    log("+ " + " ".join(str(c) for c in cmd))
    return subprocess.run(cmd, env=merged, cwd=cwd)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_port(port, proc, timeout_s=15):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def extra_p11check_args():
    raw = os.environ.get("EXTRA_P11CHECK_ARGS", "").strip()
    return raw.split() if raw else []


def provision_softhsm_windows(workdir):
    """Fetch the pinned disig portable zip (hash-verified) and unpack it."""
    dl_dir = os.path.join(workdir, "dl")
    os.makedirs(dl_dir, exist_ok=True)
    zippath = os.path.join(dl_dir, "softhsm2.zip")
    log(f"downloading {SOFTHSM_WIN_URL}")
    urllib.request.urlretrieve(SOFTHSM_WIN_URL, zippath)
    digest = sha256_file(zippath)
    if digest != SOFTHSM_WIN_SHA256:
        raise SystemExit(f"SoftHSM zip hash mismatch: {digest}")
    log("hash verified, extracting")
    with zipfile.ZipFile(zippath) as zf:
        zf.extractall(os.path.join(workdir, "softhsm-win"))
    root = os.path.join(workdir, "softhsm-win", "SoftHSM2")
    lib = os.path.join(root, "lib", "softhsm2-x64.dll")
    util = os.path.join(root, "bin", "softhsm2-util.exe")
    if not os.path.isfile(lib):
        raise SystemExit(f"expected {lib} after extraction")
    if not os.path.isfile(util):
        raise SystemExit(f"expected {util} after extraction")
    return lib, util


def provision_softhsm_unix():
    lib = next((c for c in SOFTHSM_UNIX_LIB_CANDIDATES if os.path.isfile(c)), None)
    if lib is None:
        raise SystemExit("SoftHSM2 module not found; install softhsm2 first")
    util = shutil.which("softhsm2-util")
    if util is None:
        raise SystemExit("softhsm2-util not on PATH; install softhsm2 first")
    return lib, util


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release-dir", default=None)
    ap.add_argument("--slot", type=int, default=0)
    ap.add_argument("--workdir", default=None)
    args = ap.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    release_dir = args.release_dir or os.path.join(root, "target", "release")
    exe = ".exe" if sys.platform == "win32" else ""
    daemon = os.path.join(release_dir, "pkcs11-proxy-ng" + exe)
    if sys.platform == "win32":
        shim = os.path.join(release_dir, "pkcs11_proxy_ng_shim.dll")
    elif sys.platform == "darwin":
        shim = os.path.join(release_dir, "libpkcs11_proxy_ng_shim.dylib")
    else:
        shim = os.path.join(release_dir, "libpkcs11_proxy_ng_shim.so")
    for path, what in ((daemon, "daemon binary"), (shim, "shim library")):
        if not os.path.isfile(path):
            raise SystemExit(f"{what} not found at {path}; build --release first")

    base_tmp = os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()
    workdir = args.workdir or tempfile.mkdtemp(prefix="ci-compare-", dir=base_tmp)
    os.makedirs(workdir, exist_ok=True)
    log(f"workdir: {workdir}")

    if sys.platform == "win32":
        softhsm_lib, softhsm_util = provision_softhsm_windows(workdir)
    else:
        softhsm_lib, softhsm_util = provision_softhsm_unix()
    log(f"SoftHSM module: {softhsm_lib}")

    token_dir = os.path.join(workdir, "tokens")
    os.makedirs(token_dir, exist_ok=True)
    softhsm_conf = os.path.join(workdir, "softhsm2.conf")
    with open(softhsm_conf, "w", encoding="utf-8") as f:
        f.write(
            f"directories.tokendir = {token_dir}\n"
            "objectstore.backend = file\n"
            "log.level = INFO\n"
            "slots.removable = false\n"
            "slots.mechanisms = ALL\n"
            "library.reset_on_fork = false\n"
        )
    os.environ["SOFTHSM2_CONF"] = softhsm_conf

    log("[1/5] initializing scratch SoftHSM token")
    r = run(
        [
            softhsm_util,
            "--init-token",
            "--free",
            "--label",
            TOKEN_LABEL,
            "--so-pin",
            SO_PIN,
            "--pin",
            USER_PIN,
        ]
    )
    if r.returncode != 0:
        raise SystemExit("softhsm2-util --init-token failed")

    port = free_port()
    endpoint = f"http://127.0.0.1:{port}"
    proxy_toml = os.path.join(workdir, "proxy.toml")
    with open(proxy_toml, "w", encoding="utf-8") as f:
        f.write(
            "[backend]\n"
            f'module = "{softhsm_lib}"\n'
            "\n[proxy]\n"
            "request_timeout_secs = 30\n"
            "startup_timeout_secs = 30\n"
            "shutdown_grace_secs = 30\n"
            "backend_health_consecutive_failures = 3\n"
            "\n[listener.remote]\n"
            f'bind = "127.0.0.1:{port}"\n'
            'auth = "none"\n'
            "allow_insecure_tcp = true\n"
            "\n[auth]\n"
        )

    common_p11 = [
        "--slot",
        str(args.slot),
        "--pin",
        USER_PIN,
        "--so-pin",
        SO_PIN,
        "--skip-slow",
        "--output",
        "json",
    ] + extra_p11check_args()

    direct_dir = os.path.join(workdir, "direct")
    os.makedirs(direct_dir, exist_ok=True)
    log("[2/5] pkcs11-check DIRECT against SoftHSM")
    direct = run(
        [
            "pkcs11-check",
            "test",
            "--module",
            softhsm_lib,
            "--output-file",
            os.path.join(direct_dir, "results.json"),
        ]
        + common_p11
    )
    log(f"direct exit: {direct.returncode}")

    daemon_log = os.path.join(workdir, "daemon.log")
    log(f"[3/5] starting daemon on {endpoint} (auth=none, loopback only)")
    with open(daemon_log, "wb") as logfh:
        daemon_env = dict(os.environ)
        daemon_env.setdefault("RUST_LOG", "pkcs11_proxy_ng=info")
        proc = subprocess.Popen(
            [daemon, proxy_toml],
            stdout=logfh,
            stderr=subprocess.STDOUT,
            env=daemon_env,
        )
    try:
        if not wait_for_port(port, proc):
            raise SystemExit("daemon did not bind within 15s; see daemon.log")
        with open(daemon_log, encoding="utf-8", errors="replace") as f:
            daemon_text = f.read()
        for needle in (DAEMON_LOG_TCP_WARN, DAEMON_LOG_REGISTRY):
            if needle not in daemon_text:
                raise SystemExit(f"daemon log missing {needle!r}; see daemon.log")
        log("daemon up; startup assertions observed")

        proxied_dir = os.path.join(workdir, "proxied")
        os.makedirs(proxied_dir, exist_ok=True)
        log("[4/5] pkcs11-check PROXIED against the shim")
        proxied = run(
            [
                "pkcs11-check",
                "test",
                "--module",
                shim,
                "--output-file",
                os.path.join(proxied_dir, "results.json"),
            ]
            + common_p11,
            env={
                "PKCS11_PROXY_ENDPOINT": endpoint,
                "PKCS11_PROXY_CONNECT_TIMEOUT": "10",
            },
        )
        log(f"proxied exit: {proxied.returncode}")
    finally:
        log("stopping daemon")
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()

    direct_jsonl = os.path.join(direct_dir, "report.jsonl")
    proxied_jsonl = os.path.join(proxied_dir, "report.jsonl")
    log("[5/5] differential comparison")
    diff = run(
        [
            "pkcs11-check",
            "differential",
            f"direct={direct_jsonl}",
            f"proxied={proxied_jsonl}",
        ]
    )
    log(f"differential exit: {diff.returncode}")

    print(f"workdir: {workdir}")
    if direct.returncode != 0:
        raise SystemExit(
            f"DIRECT run failed (exit {direct.returncode}) -- baseline is "
            "red, so the comparison is meaningless; see direct/results.json"
        )
    if proxied.returncode != 0:
        raise SystemExit(
            f"PROXIED run failed (exit {proxied.returncode}) while direct "
            "passed -- proxy transparency regression; see proxied/results.json"
        )
    if diff.returncode != 0:
        raise SystemExit(
            f"differential found direct-vs-proxied divergence (exit {diff.returncode})"
        )
    log("PASS: direct == proxied (strict transparency gate)")


if __name__ == "__main__":
    main()

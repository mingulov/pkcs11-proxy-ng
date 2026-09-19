#!/usr/bin/env python3
"""Direct-vs-proxied transparency gate (cross-platform CI core).

Runs the SAME pkcs11-check suite (from PyPI) twice -- once against the
SoftHSM module directly, once through the proxy shim + release daemon --
then compares the two reports with ``pkcs11-check differential``. The
shim must be indistinguishable from the backend (AGENTS.md rule 2); this
gate checks that claim within the scope below.

Scope (honest contract -- Review-A M-1): the gate is
direct-exit-0 AND proxied-exit-0 AND deterministic-KAT-verdict agreement.
The exit-0 legs catch every failure-class outcome (failed/crashed/error/
timeout, strict-xpass failure) on EVERY suite, direct or proxied. The
differential leg uses the framework default scope -- deterministic KAT
node-ids only (wycheproof/ACVP/test_cctv_*; ``differential_cmd.py`` +
``is_kat_nodeid`` in ``core/differential.py``) -- NOT every node-id.
Known residual: non-KAT outcome transitions that keep exit 0 (pass <->
skip, xfail <-> non-strict xpass) are not compared.

Why not ``differential --all``: the framework offers no proxy-aware
timing margins or flake allowance anywhere on the differential path
(verified: no margin/F19/timing support in ``core/differential.py``,
``cli/differential_cmd.py``, or ``core/compare_results.py``), so ``--all``
would trade the documented residual above for undocumented flake risk on
a daily gate -- and still would not see skip-class transitions (skips
are excluded from attempted outcomes by construction:
``_attempted_outcomes`` + ``comparable_nodeids(min_providers=2)``), so it
cannot deliver a literal "any divergence" contract either. Revisit only
with framework margin support plus a skip-transition story.

Flow mirrors scripts/test-softhsm2-smoke.sh, generalized to Linux/macOS/
Windows with stdlib only (no shell/PowerShell twin to keep in sync):

  1. provision SoftHSM2 (system install on unix; pinned disig portable
     zip, hash-verified, on Windows) and init a scratch token;
  2. write a loopback-only daemon config (auth="none", CI-only -- same
     insecure-TCP shape the smoke script asserts, never a default);
  3. run pkcs11-check DIRECT against SoftHSM;
  4. wipe + re-init the scratch token with identical params (Review-A
     M-2: framework testcases create CKA_TOKEN=True persistent objects,
     so the PROXIED phase must start from identical -- not polluted --
     token state);
  5. start the daemon, run pkcs11-check PROXIED against the shim;
  6. run ``pkcs11-check differential`` on the two report.jsonl files.

Gate (strict within scope): direct exit 0 AND proxied exit 0 AND
differential (KAT scope) exit 0.
Extra pkcs11-check args (subset tuning) pass through EXTRA_P11CHECK_ARGS
(shell-quoted; parsed with shlex.split).

Usage (after ``cargo build --release``)::

    python3 scripts/ci-direct-vs-proxy.py [--release-dir target/release]
"""

import argparse
import hashlib
import glob
import json
import os
import shlex
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
    # T2run: brew softhsm 2.7.0 installs the module flat in lib/ as .so
    # (upstream .so naming on all platforms; proven by run-3 macOS
    # diagnostic -- lib/softhsm/ carries no loadable module there).
    "/opt/homebrew/lib/libsofthsm2.so",
    "/usr/local/lib/libsofthsm2.so",
]

DAEMON_LOG_TCP_WARN = "listening on tcp without authentication"
DAEMON_LOG_REGISTRY = "mechanism registry ready"

# Fail-loud network bound for the Windows SoftHSM fetch (Review-A m-6:
# urlretrieve has no timeout parameter at all, hence urlopen below).
DOWNLOAD_TIMEOUT_S = 60


def log(msg):
    print(f"[ci-compare] {msg}", flush=True)


def run(cmd, env=None, cwd=None):
    merged = dict(os.environ)
    if env:
        merged.update(env)
    log("+ " + shlex.join(str(c) for c in cmd))
    return subprocess.run(cmd, env=merged, cwd=cwd)


def p11check_cwd():
    # T2run: on Windows, pytest emits EMPTY node-id paths when the CWD and
    # the collected tree sit on different drives (workflow checkout on D:,
    # installed package on C:) — and the KAT-scope differential matches on
    # the path portion, so it finds 0 comparable KATs (exit 2) even though
    # both phases pass. Run from the installed package dir (same drive as
    # the collected tree, located via this same interpreter) so node-ids
    # carry testcases/... paths. Unix untouched: green legs stay
    # bit-identical. Selection is unaffected (pytest -k matches names,
    # not node-id paths).
    if os.name != "nt":
        return None
    out = subprocess.run(
        [
            sys.executable,
            "-c",
            "import os, pkcs11_check; "
            "print(os.path.dirname(os.path.abspath(pkcs11_check.__file__)))",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip()


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
    return shlex.split(raw) if raw else []


def download_file(url, dest, timeout_s=DOWNLOAD_TIMEOUT_S):
    """Fetch ``url`` to ``dest`` with a fail-loud timeout (Review-A m-6)."""
    log(f"downloading {url} (timeout {timeout_s}s)")
    with urllib.request.urlopen(url, timeout=timeout_s) as resp, open(
        dest, "wb"
    ) as out:
        shutil.copyfileobj(resp, out)


def safe_extractall(zip_path, dest):
    """Unpack ``zip_path`` into ``dest``, refusing ZipSlip escapes (m-6).

    The pinned-hash check upstream mitigates a hostile zip, but the guard
    costs nothing and fails loud on absolute members or ``..`` escapes.
    """
    base = os.path.realpath(dest)
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            target = os.path.realpath(os.path.join(dest, member.filename))
            if target != base and not target.startswith(base + os.sep):
                raise SystemExit(f"zip member escapes destination: {member.filename!r}")
        zf.extractall(dest)


def init_token_argv(softhsm_util):
    """softhsm2-util argv that provisions the scratch token (Review-A M-2).

    Single source of the init params (label/PINs): both phases call this
    same helper, so identical provisioning holds by construction.
    """
    return [
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


def init_scratch_token(softhsm_util):
    r = run(init_token_argv(softhsm_util))
    if r.returncode != 0:
        raise SystemExit("softhsm2-util --init-token failed")


def reset_token_state(token_dir, softhsm_util):
    """Wipe ``token_dir`` and re-init an identical scratch token (M-2).

    Called between the DIRECT and PROXIED phases so both runs start from
    identical token state; DIRECT-phase CKA_TOKEN=True objects cannot leak
    into the PROXIED run. Nothing holds the token open at this point (the
    DIRECT pkcs11-check process has exited, the daemon starts later).
    """
    log("re-initializing scratch token for the PROXIED phase")
    shutil.rmtree(token_dir, ignore_errors=True)
    os.makedirs(token_dir, exist_ok=True)
    init_scratch_token(softhsm_util)


def differential_argv(direct_jsonl, proxied_jsonl):
    """``pkcs11-check differential`` argv (Review-A M-1: KAT default scope).

    Deliberately WITHOUT --all -- see the module docstring for the
    recorded decision. Both report.jsonl inputs must exist with sibling
    results.json provenance or the framework fails loud (exit 2).
    """
    return [
        "pkcs11-check",
        "differential",
        f"direct={direct_jsonl}",
        f"proxied={proxied_jsonl}",
    ]


def differential_jsonl(report_jsonl):
    """Sibling copy of ``report.jsonl`` the framework differential parses.

    T2run: pkcs11-check 0.2.0's own report writer emits per-unit
    session-collection ``CollectReport`` records with a blank nodeid,
    which its differential reader rejects ("invalid CollectReport",
    exit 2 -- run-4 ubuntu proved exit-0x2 plus identical summaries
    while the differential died on line 239). Those records carry no
    test verdicts (the KAT scope compares TestReport node-ids only),
    so drop exactly them into a same-directory copy (sibling
    results.json provenance still resolves) and compare the copies.
    Verdict scope is unchanged; the count is logged for the record.
    """
    out = os.path.join(os.path.dirname(report_jsonl), "report.differential.jsonl")
    dropped = 0
    with open(report_jsonl, encoding="utf-8") as src, open(out, "w", encoding="utf-8") as dst:
        for line in src:
            record = json.loads(line) if line.strip() else None
            if (
                isinstance(record, dict)
                and record.get("$report_type") == "CollectReport"
                and not str(record.get("nodeid") or "").strip()
            ):
                dropped += 1
                continue
            dst.write(line)
    log(f"differential input {os.path.basename(report_jsonl)}: dropped {dropped} blank CollectReports")
    return out


def provision_softhsm_windows(workdir):
    """Fetch the pinned disig portable zip (hash-verified) and unpack it."""
    dl_dir = os.path.join(workdir, "dl")
    os.makedirs(dl_dir, exist_ok=True)
    zippath = os.path.join(dl_dir, "softhsm2.zip")
    download_file(SOFTHSM_WIN_URL, zippath)
    digest = sha256_file(zippath)
    if digest != SOFTHSM_WIN_SHA256:
        raise SystemExit(f"SoftHSM zip hash mismatch: {digest}")
    log("hash verified, extracting")
    safe_extractall(zippath, os.path.join(workdir, "softhsm-win"))
    root = os.path.join(workdir, "softhsm-win", "SoftHSM2")
    lib = os.path.join(root, "lib", "softhsm2-x64.dll")
    util = os.path.join(root, "bin", "softhsm2-util.exe")
    if not os.path.isfile(lib):
        raise SystemExit(f"expected {lib} after extraction")
    if not os.path.isfile(util):
        raise SystemExit(f"expected {util} after extraction")
    # T2run: the portable README requires the lib/ dir on PATH --
    # softhsm2-util.exe LoadLibrary()s "softhsm2.dll" by bare name
    # (run-5 win64: 0x7E without it, despite a correct desktop CRT).
    os.environ["PATH"] = os.path.join(root, "lib") + os.pathsep + os.environ.get("PATH", "")
    return lib, util


def _resolve_brew_softhsm():
    """Locate the brew SoftHSM module without hard-coding its layout.

    T2run: brew's softhsm layout varies by version (2.7.0 keeps the
    module under lib/softhsm/ reached via the lib/softhsm symlink;
    older layouts used lib/softhsm/*.dylib), so glob the live
    prefixes and the versioned Cellar instead of trusting one path.
    Static archives (.a) are never loadable modules and are skipped
    (run-5 macOS picked libsofthsm2.a first). Returns the first
    loadable-looking module or None.
    """
    prefixes = ["/opt/homebrew", "/usr/local"]
    brew = shutil.which("brew")
    if brew is not None:
        try:
            out = subprocess.run(
                [brew, "--prefix", "softhsm"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if out.returncode == 0 and out.stdout.strip():
                prefixes.insert(0, out.stdout.strip())
        except (OSError, subprocess.SubprocessError):
            pass
    patterns = []
    for prefix in prefixes:
        patterns.append(os.path.join(prefix, "lib", "libsofthsm2.*"))
        patterns.append(os.path.join(prefix, "lib", "softhsm", "libsofthsm2.*"))
    for cellar in ("/opt/homebrew/Cellar/softhsm", "/usr/local/Cellar/softhsm"):
        patterns.append(os.path.join(cellar, "*", "lib", "libsofthsm2.*"))
        patterns.append(os.path.join(cellar, "*", "lib", "softhsm", "libsofthsm2.*"))
    for pattern in patterns:
        for hit in sorted(glob.glob(pattern)):
            if hit.lower().endswith(".a"):
                continue  # static archive: never dlopenable
            if os.path.isfile(hit):  # follows links; drops dangling ones
                return hit
    return None


def provision_softhsm_unix():
    lib = next((c for c in SOFTHSM_UNIX_LIB_CANDIDATES if os.path.isfile(c)), None)
    if lib is None and sys.platform == "darwin":
        lib = _resolve_brew_softhsm()
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

    log("[1/6] initializing scratch SoftHSM token")
    init_scratch_token(softhsm_util)

    port = free_port()
    endpoint = f"http://127.0.0.1:{port}"
    proxy_toml = os.path.join(workdir, "proxy.toml")
    # T2run: escape backslashes for the TOML basic string — a raw Windows
    # path (D:\a\...) fails to parse (`\a` is an invalid escape) and the
    # daemon never binds. No-op on Unix (no backslashes in the path).
    module_toml = softhsm_lib.replace("\\", "\\\\")
    with open(proxy_toml, "w", encoding="utf-8") as f:
        f.write(
            "[backend]\n"
            f'module = "{module_toml}"\n'
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
    p11_cwd = p11check_cwd()
    if p11_cwd:
        log(f"pkcs11-check cwd (Windows node-id paths): {p11_cwd}")
    log("[2/6] pkcs11-check DIRECT against SoftHSM")
    direct = run(
        [
            "pkcs11-check",
            "test",
            "--module",
            softhsm_lib,
            "--output-file",
            os.path.join(direct_dir, "results.json"),
        ]
        + common_p11,
        cwd=p11_cwd,
    )
    log(f"direct exit: {direct.returncode}")

    # M-2: both phases start from identically-provisioned token state.
    log("[3/6] resetting scratch token to identical state")
    reset_token_state(token_dir, softhsm_util)

    daemon_log = os.path.join(workdir, "daemon.log")
    log(f"[4/6] starting daemon on {endpoint} (auth=none, loopback only)")
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
        log("[5/6] pkcs11-check PROXIED against the shim")
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
            cwd=p11_cwd,
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
    log("[6/6] differential comparison (deterministic-KAT scope)")
    diff = run(
        differential_argv(
            differential_jsonl(direct_jsonl), differential_jsonl(proxied_jsonl)
        )
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
            "differential found direct-vs-proxied KAT-verdict divergence "
            f"(exit {diff.returncode})"
        )
    log("PASS: both runs exit 0 and KAT verdicts agree (scoped gate)")


if __name__ == "__main__":
    main()

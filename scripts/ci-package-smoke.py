#!/usr/bin/env python3
"""Reusable packaged-artifact smoke contract (Stage B, Task 5a).

Verifies the exact binaries just produced -- never workspace outputs --
then proves real provider operations through them:

* ``linux-bundle``: extract the exact Linux GNU tarball, check
  hashes/materials against its build provenance, and run the extracted
  daemon/shim/CLI through a SoftHSM session/login/keygen/RSA-sign flow.
* ``windows-bundle``: extract the exact Windows MSVC ZIP, check it, and
  execute the packaged daemon/CLI plus the shim DLL through a real
  provider-backed session via the shipped ``cross_width_smoke.exe``,
  which needs a live configured daemon/provider and scratch token.
* ``macos-bundle``: extract the exact macOS arm64 tarball, check
  hashes/materials against its build provenance, strip the Gatekeeper
  quarantine xattrs macOS attaches to downloaded archives (byte hashes
  are verified first, so the strip cannot mask tampering), and run the
  extracted daemon/shim/CLI through the Unix SoftHSM flow.
* ``apk-verify``: check the exact Alpine APK set members (own licenses,
  upstream notices/inventory/provenance/materials) and record the
  sha256 of each binary payload (``--hash-output``) as the reference
  for install-fidelity comparison.
* ``installed-verify``: hash the installed daemon/shim/CLI binaries
  and compare against the ``apk-verify`` reference, refusing any
  mismatch (proves the install delivered the verified payload bytes).
* ``installed-smoke``: run the provider-operation flow against explicit
  installed daemon/shim/CLI paths (the Alpine installed lane).

The same contract verifies registry release bundles after publication,
before GitHub asset approval. All artifact paths are explicit required
arguments: there is no default and no fallback.

Provider chain exercised on Unix (proves the shim's
C_GetSlotList -> C_OpenSession -> C_Login -> C_GenerateKey ->
C_SignInit / C_Sign path end to end against a real backend):
slot discovery, login, RSA-2048 key generation, SHA256-RSA-PKCS sign
with a non-trivial signature size check.

Daemon lifecycle, SoftHSM provisioning, and ZIP safety helpers are
reused from scripts/ci-direct-vs-proxy.py. Hash enforcement for the
Windows SoftHSM archive lives solely in that helper's
provision_softhsm_windows; this module keeps no separate verifier, only
a drift-checked mirror of the pin below.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

# Drift-checked mirror of the pin enforced by provision_softhsm_windows
# (the single enforcement point); not enforced here.
SOFTHSM_WIN_SHA256 = "85273BCC1A6B90E877F7BB4F7E90221D57103D8F5241D154A79DD730A135B910"

DAEMON_LOG_TCP_WARN = "listening on tcp without authentication"
DAEMON_LOG_REGISTRY = "mechanism registry ready"

APK_PACKAGES = (
    "pkcs11-proxy-ng-shim",
    "pkcs11-proxy-ng-daemon",
    "pkcs11-proxy-ng-cli",
    "pkcs11-proxy-ng-compat",
)
APK_NOTICE_MEMBERS = (
    "THIRD_PARTY_NOTICES",
    "notice-inventory.json",
    "build-provenance.json",
    "license-material/ring-0.17.14/licenses/LICENSE",
    "license-material/rust-std/COPYRIGHT-library.html",
)
# Installed-binary payload each APK must deliver (APKBUILD install
# paths, matched by suffix inside the APK tar). The sha256 of these
# payload bytes is the install-fidelity reference: installed-verify
# compares the on-disk installed files against it.
APK_BINARY_MEMBERS = (
    ("daemon", "pkcs11-proxy-ng-daemon", "usr/bin/pkcs11-proxy-ng"),
    ("shim", "pkcs11-proxy-ng-shim", "usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so"),
    ("cli", "pkcs11-proxy-ng-cli", "usr/bin/pkcs11-proxy-ng-cli"),
)


def _load_compare():
    compare_path = Path(__file__).resolve().parent / "ci-direct-vs-proxy.py"
    module_name = "ci_direct_vs_proxy_reused"
    spec = importlib.util.spec_from_file_location(module_name, compare_path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load helper {compare_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_compare = _load_compare()

# Reused lifecycle/provisioning helpers (single implementation lives in
# scripts/ci-direct-vs-proxy.py).
free_port = _compare.free_port
safe_extract_zip = _compare.safe_extractall


def log(msg):
    print(f"[package-smoke] {msg}", flush=True)


def require_file(path, label):
    if not path or not os.path.isfile(path):
        raise SystemExit(f"{label} not found at {path!r}; pass the exact artifact path")
    return os.fspath(path)


def require_executable(path, label):
    require_file(path, label)
    if not os.access(path, os.X_OK):
        raise SystemExit(f"{label} at {path!r} is not executable")
    return os.fspath(path)


def require_dir(path, label):
    if not path or not os.path.isdir(path):
        raise SystemExit(f"{label} not found at {path!r}; pass the exact directory")
    return os.fspath(path)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def provider_operation_chain():
    """Human-readable provider chain this contract proves (not --help)."""
    return (
        "C_GetSlotList -> C_OpenSession -> C_Login -> C_GenerateKey -> "
        "C_SignInit / C_Sign against a scratch SoftHSM token"
    )


def run_provider_step(cmd, label, env=None):
    """Run one provider step; any nonzero exit fails the smoke loudly."""
    merged = dict(os.environ)
    if env:
        merged.update(env)
    log("+ " + shlex.join(str(part) for part in cmd))
    result = subprocess.run(cmd, env=merged, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        output = (result.stdout or "")[-4000:]
        raise SystemExit(f"provider step {label!r} failed (exit {result.returncode}):\n{output}")
    return result


def wait_for_daemon(port, proc, timeout_s=30):
    return bool(_compare.wait_for_port(port, proc, timeout_s))


def require_daemon_ready(log_path, port, proc, timeout_s=30):
    if wait_for_daemon(port, proc, timeout_s):
        return
    try:
        with open(log_path, encoding="utf-8", errors="replace") as handle:
            tail = handle.read()[-4000:]
    except OSError:
        tail = "(daemon log unreadable)"
    raise SystemExit(
        f"daemon did not bind within {timeout_s}s; log retained at {log_path}:\n{tail}"
    )


def write_daemon_config(path, module, port):
    module_toml = module.replace("\\", "\\\\")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
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
    return path


def write_softhsm_conf(path, token_dir):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            f"directories.tokendir = {token_dir}\n"
            "objectstore.backend = file\n"
            "log.level = INFO\n"
            "slots.removable = false\n"
            "slots.mechanisms = ALL\n"
            "library.reset_on_fork = false\n"
        )
    return path


def verify_prepared_bundle(bundle_dir, provenance_path):
    """Check extracted bundle bytes against its build provenance.

    Refuses tampered/missing binaries, missing notices, and unreadable
    provenance. Returns the verified artifact summary.
    """
    bundle = Path(bundle_dir)
    provenance_file = Path(provenance_path)
    if not bundle.is_dir():
        raise SystemExit(f"bundle directory not found: {bundle}")
    try:
        provenance = json.loads(provenance_file.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise SystemExit(f"cannot read bundle provenance {provenance_file}: {exc}") from exc
    if not isinstance(provenance, dict) or not isinstance(provenance.get("artifacts"), list):
        raise SystemExit(f"bundle provenance has no artifact inventory: {provenance_file}")
    notices = list(bundle.rglob("THIRD_PARTY_NOTICES"))
    if not notices or not any(item.is_file() and item.stat().st_size for item in notices):
        raise SystemExit(f"bundle lacks readable THIRD_PARTY_NOTICES: {bundle}")
    verified = []
    for record in provenance["artifacts"]:
        name = record.get("name") if isinstance(record, dict) else None
        if not name or "/" in name or "\\" in name:
            raise SystemExit(f"bundle provenance has unsafe artifact name: {name!r}")
        hits = [item for item in bundle.rglob(name) if item.is_file()]
        if len(hits) != 1:
            raise SystemExit(f"bundle has {len(hits)} copies of {name}; expected exactly one")
        staged = hits[0]
        size = staged.stat().st_size
        if not isinstance(record.get("size"), int) or size != record["size"] or size <= 0:
            raise SystemExit(f"prepared binary size differs from provenance: {name}")
        if sha256_file(staged) != record.get("sha256"):
            raise SystemExit(f"prepared binary hash differs from provenance: {name}")
        verified.append(name)
    if not verified:
        raise SystemExit(f"bundle provenance lists no artifacts: {provenance_file}")
    log(f"bundle verified: {len(verified)} binaries match provenance; notices present")
    return {"binaries": verified, "target": provenance.get("target"),
            "source_mode": provenance.get("source_mode")}


def safe_extract_tarball(tarball, dest):
    """Unpack a bundle tarball, refusing path escapes and links."""
    require_file(tarball, "bundle tarball")
    os.makedirs(dest, exist_ok=True)
    base = os.path.realpath(dest)
    try:
        with tarfile.open(tarball, "r:*") as archive:
            for member in archive:
                target = os.path.realpath(os.path.join(dest, member.name))
                if target != base and not target.startswith(base + os.sep):
                    raise SystemExit(f"tar member escapes destination: {member.name!r}")
                if member.issym() or member.islnk():
                    raise SystemExit(f"tar member is a link: {member.name!r}")
            archive.extractall(dest, filter="data")
    except (OSError, tarfile.TarError) as exc:
        raise SystemExit(f"cannot extract bundle tarball {tarball}: {exc}") from exc
    return dest


def find_staged(bundle_root, name):
    hits = [item for item in Path(bundle_root).rglob(name) if item.is_file()]
    if len(hits) != 1:
        raise SystemExit(f"bundle has {len(hits)} copies of {name}; expected exactly one")
    return str(hits[0])


def unix_provider_smoke(daemon, shim, cli, workdir, softhsm_lib=None, softhsm_util=None):
    """Run the real SoftHSM session/login/keygen/sign flow (Unix)."""
    daemon = require_executable(daemon, "daemon binary")
    shim = require_file(shim, "shim library")
    cli = require_executable(cli, "CLI binary")
    workdir = require_dir(workdir, "smoke workdir")
    if softhsm_lib is None or softhsm_util is None:
        softhsm_lib, softhsm_util = _compare.provision_softhsm_unix()
    else:
        require_file(softhsm_lib, "SoftHSM module")
        require_executable(softhsm_util, "softhsm2-util")
    pkcs11_tool = shutil.which("pkcs11-tool")
    if pkcs11_tool is None:
        raise SystemExit("pkcs11-tool not on PATH; install OpenSC first")
    token_dir = os.path.join(workdir, "tokens")
    os.makedirs(token_dir, exist_ok=True)
    os.environ["SOFTHSM2_CONF"] = write_softhsm_conf(os.path.join(workdir, "softhsm2.conf"),
                                                    token_dir)
    log(f"scratch token in {token_dir}")
    # Single provisioning source: the flow below addresses the scratch
    # token this shared helper created (its label/PINs).
    _compare.init_scratch_token(softhsm_util)
    port = free_port()
    endpoint = f"http://127.0.0.1:{port}"
    proxy_toml = write_daemon_config(os.path.join(workdir, "proxy.toml"), softhsm_lib, port)
    daemon_log = os.path.join(workdir, "daemon.log")
    log(f"starting packaged daemon {daemon} on {endpoint}")
    with open(daemon_log, "wb") as logfh:
        env = dict(os.environ)
        env.setdefault("RUST_LOG", "pkcs11_proxy_ng=info")
        proc = subprocess.Popen([daemon, proxy_toml], stdout=logfh,
                                stderr=subprocess.STDOUT, env=env)
    try:
        require_daemon_ready(daemon_log, port, proc)
        with open(daemon_log, encoding="utf-8", errors="replace") as handle:
            daemon_text = handle.read()
        for needle in (DAEMON_LOG_TCP_WARN, DAEMON_LOG_REGISTRY):
            if needle not in daemon_text:
                raise SystemExit(f"daemon log missing {needle!r}; see {daemon_log}")
        log("daemon up; startup assertions observed")
        smoke_env = {"PKCS11_PROXY_ENDPOINT": endpoint,
                     "PKCS11_PROXY_CONNECT_TIMEOUT": "10"}
        slots = run_provider_step([pkcs11_tool, "--module", shim, "--list-slots"],
                                  "list-slots", env=smoke_env)
        if _compare.TOKEN_LABEL not in slots.stdout:
            raise SystemExit(f"token {_compare.TOKEN_LABEL!r} missing from slot list")
        run_provider_step([pkcs11_tool, "--module", shim, "--token-label", _compare.TOKEN_LABEL,
                           "--login", "--pin", _compare.USER_PIN, "--keypairgen",
                           "--key-type", "rsa:2048", "--label", "pkg-smoke-key", "--id", "01"],
                          "keygen", env=smoke_env)
        data_path = os.path.join(workdir, "data.bin")
        sig_path = os.path.join(workdir, "sig.bin")
        with open(data_path, "wb") as handle:
            handle.write(os.urandom(256))
        run_provider_step([pkcs11_tool, "--module", shim, "--token-label", _compare.TOKEN_LABEL,
                           "--login", "--pin", _compare.USER_PIN, "--sign",
                           "--mechanism", "SHA256-RSA-PKCS",
                           "--input-file", data_path, "--output-file", sig_path],
                          "sign", env=smoke_env)
        size = os.path.getsize(sig_path)
        if size < 200:
            raise SystemExit(f"signature size {size} too small for RSA-2048")
        log(f"produced {size}-byte RSA-2048 signature through {shim}")
        run_provider_step([cli, "--version"], "cli-version")
    finally:
        log("stopping smoke-owned daemon")
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
    log(f"PASS: {provider_operation_chain()}")
    return {"endpoint": endpoint, "daemon_log": daemon_log}


def run_cross_width_smoke(smoke_exe, shim_dll, endpoint):
    """Execute the packaged DLL through a live provider-backed session."""
    smoke_exe = require_executable(smoke_exe, "cross_width_smoke.exe")
    shim_dll = require_file(shim_dll, "shim DLL")
    if not endpoint:
        raise SystemExit("cross_width_smoke needs a live daemon endpoint")
    return run_provider_step([smoke_exe, shim_dll], "cross-width-smoke",
                             env={"PKCS11_PROXY_ENDPOINT": endpoint,
                                  "PKCS11_PROXY_CONNECT_TIMEOUT": "10"})


def windows_provider_smoke(daemon, cli, shim_dll, smoke_exe, workdir):
    """Run the real provider-backed flow on a native Windows runner."""
    daemon = require_executable(daemon, "daemon binary")
    cli = require_executable(cli, "CLI binary")
    shim_dll = require_file(shim_dll, "shim DLL")
    smoke_exe = require_executable(smoke_exe, "cross_width_smoke.exe")
    workdir = require_dir(workdir, "smoke workdir")
    softhsm_lib, softhsm_util = _compare.provision_softhsm_windows(workdir)
    log(f"SoftHSM module: {softhsm_lib}")
    token_dir = os.path.join(workdir, "tokens")
    os.makedirs(token_dir, exist_ok=True)
    os.environ["SOFTHSM2_CONF"] = write_softhsm_conf(os.path.join(workdir, "softhsm2.conf"),
                                                    token_dir)
    _compare.init_scratch_token(softhsm_util)
    port = free_port()
    endpoint = f"http://127.0.0.1:{port}"
    proxy_toml = write_daemon_config(os.path.join(workdir, "proxy.toml"), softhsm_lib, port)
    daemon_log = os.path.join(workdir, "daemon.log")
    log(f"starting packaged daemon {daemon} on {endpoint}")
    with open(daemon_log, "wb") as logfh:
        env = dict(os.environ)
        env.setdefault("RUST_LOG", "pkcs11_proxy_ng=info")
        proc = subprocess.Popen([daemon, proxy_toml], stdout=logfh,
                                stderr=subprocess.STDOUT, env=env)
    try:
        require_daemon_ready(daemon_log, port, proc)
        with open(daemon_log, encoding="utf-8", errors="replace") as handle:
            daemon_text = handle.read()
        for needle in (DAEMON_LOG_TCP_WARN, DAEMON_LOG_REGISTRY):
            if needle not in daemon_text:
                raise SystemExit(f"daemon log missing {needle!r}; see {daemon_log}")
        run_cross_width_smoke(smoke_exe, shim_dll, endpoint)
        run_provider_step([cli, "--version"], "cli-version")
    finally:
        log("stopping smoke-owned daemon")
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
    log("PASS: packaged daemon/CLI/DLL served a live provider-backed session")
    return {"endpoint": endpoint, "daemon_log": daemon_log}


def apk_members(apk_path):
    """List data members of one ``.apk`` (a gzipped tar)."""
    require_file(apk_path, "APK file")
    try:
        with tarfile.open(apk_path, "r:gz") as archive:
            return archive.getnames()
    except (OSError, tarfile.TarError) as exc:
        raise SystemExit(f"cannot list APK members {apk_path}: {exc}") from exc


def apk_payload_bytes(apk_path, suffix):
    """Return ``(member_name, raw_bytes)`` for one payload member of an APK.

    Refuses a missing or ambiguous payload so a repackaged APK cannot
    silently drop or duplicate the installed binary.
    """
    require_file(apk_path, "APK file")
    try:
        with tarfile.open(apk_path, "r:gz") as archive:
            candidates = [m for m in archive.getmembers()
                          if m.isfile() and (m.name == suffix or m.name.endswith("/" + suffix))]
            if len(candidates) != 1:
                raise SystemExit(f"{apk_path} has {len(candidates)} payload members"
                                 f" matching {suffix}; expected exactly one")
            member = candidates[0]
            extracted = archive.extractfile(member)
            if extracted is None:
                raise SystemExit(f"{apk_path} payload {member.name} is unreadable")
            return member.name, extracted.read()
    except tarfile.TarError as exc:
        raise SystemExit(f"cannot read APK payload {apk_path}: {exc}") from exc


def verify_apk_set(apk_dir, hash_output=None):
    """Check the exact four-APK set and their notice/provenance carriage.

    When ``hash_output`` is given, additionally hash each binary payload
    from the APK tars and write the ``{role: {package, member, sha256}}``
    reference JSON there for ``installed-verify`` to compare against.
    """
    apk_dir = require_dir(apk_dir, "APK directory")
    hits = {}
    for package in APK_PACKAGES:
        matches = sorted(Path(apk_dir).rglob(f"{package}-*.apk"))
        matches = [item for item in matches if item.is_file()]
        if len(matches) != 1:
            raise SystemExit(f"APK set has {len(matches)} {package} files; expected exactly one")
        hits[package] = matches[0]
    for package, apk_path in hits.items():
        members = apk_members(str(apk_path))
        if package == "pkcs11-proxy-ng-compat":
            continue
        for required in ("LICENSE-APACHE", "LICENSE-MIT", *APK_NOTICE_MEMBERS):
            if not any(member.endswith(required) for member in members):
                raise SystemExit(f"{apk_path.name} lacks packaged member {required}")
    log(f"APK set verified: {len(hits)} packages with notices/provenance/materials")
    if hash_output is None:
        return {name: str(path) for name, path in hits.items()}
    reference = {}
    for role, package, suffix in APK_BINARY_MEMBERS:
        member, payload = apk_payload_bytes(str(hits[package]), suffix)
        digest = hashlib.sha256(payload).hexdigest()
        reference[role] = {"package": package, "member": member, "sha256": digest}
        log(f"payload hash {role} ({package}:{member}): {digest}")
    with open(hash_output, "w", encoding="utf-8") as handle:
        json.dump({"binaries": reference}, handle, indent=2, sort_keys=True)
        handle.write("\n")
    log(f"payload hashes recorded at {hash_output}")
    return {name: str(path) for name, path in hits.items()}


def verify_installed_hashes(daemon, shim, cli, expected_path, record_path=None):
    """Hash the installed binaries and compare against the APK payload reference.

    Refuses any mismatch (proves the install delivered the verified
    payload bytes). When ``record_path`` is given, writes the installed
    ``{role: {path, sha256}}`` hashes there as job evidence. Returns the
    installed hashes.
    """
    daemon = require_executable(daemon, "installed daemon binary")
    shim = require_file(shim, "installed shim library")
    cli = require_executable(cli, "installed CLI binary")
    require_file(expected_path, "expected payload hashes")
    try:
        expected = json.loads(Path(expected_path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise SystemExit(f"cannot read payload hashes {expected_path}: {exc}") from exc
    if not isinstance(expected, dict) or not isinstance(expected.get("binaries"), dict):
        raise SystemExit(f"payload hashes have no binary inventory: {expected_path}")
    installed = {"daemon": daemon, "shim": shim, "cli": cli}
    checked = {}
    for role, path in installed.items():
        record = expected["binaries"].get(role)
        if not isinstance(record, dict) or not record.get("sha256"):
            raise SystemExit(f"payload hashes lack a reference for {role}: {expected_path}")
        digest = sha256_file(path)
        if digest != record["sha256"]:
            raise SystemExit(f"installed {role} hash differs from APK payload:"
                             f" {path} ({digest} != {record['sha256']})")
        checked[role] = {"path": path, "sha256": digest}
        log(f"installed hash {role} ({path}): {digest} matches payload")
    if record_path is not None:
        with open(record_path, "w", encoding="utf-8") as handle:
            json.dump({"binaries": checked}, handle, indent=2, sort_keys=True)
            handle.write("\n")
        log(f"installed hashes recorded at {record_path}")
    return checked


def cmd_linux_bundle(args):
    tarball = require_file(args.bundle, "Linux bundle tarball")
    workdir = require_dir(args.workdir, "smoke workdir")
    extracted = os.path.join(workdir, "extracted")
    safe_extract_tarball(tarball, extracted)
    provenance_hits = [str(item) for item in Path(extracted).rglob("build-provenance.json")]
    if len(provenance_hits) != 1:
        raise SystemExit(f"bundle has {len(provenance_hits)} build-provenance.json files")
    verify_prepared_bundle(extracted, provenance_hits[0])
    daemon = find_staged(extracted, "pkcs11-proxy-ng")
    cli = find_staged(extracted, "pkcs11-proxy-ng-cli")
    shim = find_staged(extracted, "libpkcs11_proxy_ng_shim.so")
    return unix_provider_smoke(daemon, shim, cli, workdir)


def cmd_macos_bundle(args):
    tarball = require_file(args.bundle, "macOS bundle tarball")
    workdir = require_dir(args.workdir, "smoke workdir")
    extracted = os.path.join(workdir, "extracted")
    safe_extract_tarball(tarball, extracted)
    provenance_hits = [str(item) for item in Path(extracted).rglob("build-provenance.json")]
    if len(provenance_hits) != 1:
        raise SystemExit(f"bundle has {len(provenance_hits)} build-provenance.json files")
    verify_prepared_bundle(extracted, provenance_hits[0])
    if sys.platform == "darwin":
        # Downloaded archives arrive quarantined; Gatekeeper would kill the
        # extracted Mach-O binaries (SIGKILL) and refuse the dylib at dlopen.
        # Hashes are already verified above, so clearing xattrs only drops
        # the OS tag — it cannot hide a byte change.
        cleared = subprocess.run(["xattr", "-cr", extracted],
                                 text=True, capture_output=True)
        if cleared.returncode != 0:
            raise SystemExit(f"xattr -cr failed on {extracted}: {cleared.stderr.strip()}")
        log("cleared quarantine xattrs from extracted bundle")
    daemon = find_staged(extracted, "pkcs11-proxy-ng")
    cli = find_staged(extracted, "pkcs11-proxy-ng-cli")
    shim = find_staged(extracted, "libpkcs11_proxy_ng_shim.dylib")
    return unix_provider_smoke(daemon, shim, cli, workdir)


def cmd_windows_bundle(args):
    archive = require_file(args.bundle, "Windows bundle ZIP")
    workdir = require_dir(args.workdir, "smoke workdir")
    extracted = os.path.join(workdir, "extracted")
    os.makedirs(extracted, exist_ok=True)
    safe_extract_zip(archive, extracted)
    provenance_hits = [str(item) for item in Path(extracted).rglob("build-provenance.json")]
    if len(provenance_hits) != 1:
        raise SystemExit(f"bundle has {len(provenance_hits)} build-provenance.json files")
    verify_prepared_bundle(extracted, provenance_hits[0])
    daemon = find_staged(extracted, "pkcs11-proxy-ng.exe")
    cli = find_staged(extracted, "pkcs11-proxy-ng-cli.exe")
    shim = find_staged(extracted, "pkcs11_proxy_ng_shim.dll")
    smoke_exe = find_staged(extracted, "cross_width_smoke.exe")
    return windows_provider_smoke(daemon, cli, shim, smoke_exe, workdir)


def cmd_apk_verify(args):
    return verify_apk_set(args.apk_dir, hash_output=args.hash_output)


def cmd_installed_verify(args):
    return verify_installed_hashes(args.daemon, args.shim, args.cli,
                                   args.expected_hashes, record_path=args.record_out)


def cmd_installed_smoke(args):
    return unix_provider_smoke(args.daemon, args.shim, args.cli, args.workdir)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    linux = commands.add_parser("linux-bundle")
    linux.add_argument("--bundle", required=True)
    linux.add_argument("--workdir", required=True)
    windows = commands.add_parser("windows-bundle")
    windows.add_argument("--bundle", required=True)
    windows.add_argument("--workdir", required=True)
    macos = commands.add_parser("macos-bundle")
    macos.add_argument("--bundle", required=True)
    macos.add_argument("--workdir", required=True)
    apk = commands.add_parser("apk-verify")
    apk.add_argument("--apk-dir", required=True)
    apk.add_argument("--hash-output", default=None)
    verify = commands.add_parser("installed-verify")
    verify.add_argument("--daemon", required=True)
    verify.add_argument("--shim", required=True)
    verify.add_argument("--cli", required=True)
    verify.add_argument("--expected-hashes", required=True)
    verify.add_argument("--record-out", default=None)
    installed = commands.add_parser("installed-smoke")
    installed.add_argument("--daemon", required=True)
    installed.add_argument("--shim", required=True)
    installed.add_argument("--cli", required=True)
    installed.add_argument("--workdir", required=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    handlers = {"linux-bundle": cmd_linux_bundle, "windows-bundle": cmd_windows_bundle,
                "macos-bundle": cmd_macos_bundle,
                "apk-verify": cmd_apk_verify, "installed-verify": cmd_installed_verify,
                "installed-smoke": cmd_installed_smoke}
    handlers[args.command](args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Two exact mutation controls in committed, isolated Linux source snapshots.

--output must be absolute and outside the caller checkout/donor: even a failed
invocation must never overwrite a source or ordinary Cargo output with a receipt.
No provider, full-suite, or release qualification is performed.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
LOCK = Path("/tmp/pkcs11-proxy-testing-feedback-cargo.lock")
LOG_LIMIT = 8 * 1024 * 1024
BUILD_CAP = 90
TEST_CAP = 10
AUX_CAP = 30
EPHEMERAL_REMOVAL_CAP = 60
INTERRUPTED_SIGNAL = None


class PanelError(RuntimeError):
    pass


class PanelArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise PanelError(message)


def sha256(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def canonical_hash(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def safe_relative(value):
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise PanelError("invalid source-relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise PanelError(f"escaping/noncanonical source path: {value!r}")
    return value


def require_keys(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise PanelError(f"malformed {label}: requires exactly {sorted(keys)}")


def load_manifest(path, selected):
    manifest = json.loads(path.read_text())
    require_keys(manifest, ("schema", "cases"), "manifest")
    if manifest["schema"] != "mutation-panel-manifest/v1":
        raise PanelError("unsupported mutation panel manifest schema")
    cases = manifest["cases"]
    if not isinstance(cases, list) or not cases:
        raise PanelError("manifest selects zero mutation cases")
    ids = []
    for case in cases:
        require_keys(
            case,
            ("id", "source", "before", "after", "package", "target", "primary", "control", "panic"),
            "mutation case",
        )
        if not isinstance(case["id"], str) or not re.fullmatch(r"[a-z][a-z0-9-]*", case["id"]):
            raise PanelError("invalid exact case ID")
        ids.append(case["id"])
        safe_relative(case["source"])
        for key in ("before", "after"):
            if not isinstance(case[key], str) or not case[key] or len(case[key]) > 16384:
                raise PanelError("mutation requires bounded nonempty exact bytes")
        if case["before"] == case["after"]:
            raise PanelError("mutation replacement must change source bytes")
        if not isinstance(case["package"], str) or not re.fullmatch(
            r"[a-z][a-z0-9-]+", case["package"]
        ):
            raise PanelError("invalid Cargo package selector")
        require_keys(case["target"], ("kind", "name"), "Cargo target")
        if case["target"]["kind"] not in ("lib", "test") or not re.fullmatch(
            r"[a-zA-Z_][a-zA-Z0-9_-]*", case["target"]["name"]
        ):
            raise PanelError("invalid exact Cargo target selector")
        for key in ("primary", "control"):
            if not isinstance(case[key], str) or not re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_:]*", case[key]
            ):
                raise PanelError("invalid exact test selector")
        if case["primary"] == case["control"]:
            raise PanelError("primary and positive control must be distinct")
        require_keys(case["panic"], ("source", "fragments"), "panic contract")
        safe_relative(case["panic"]["source"])
        fragments = case["panic"]["fragments"]
        if (
            not isinstance(fragments, list)
            or not fragments
            or any(
                not isinstance(item, str) or not item or "\n" in item or len(item) > 4096
                for item in fragments
            )
        ):
            raise PanelError("panic contract needs bounded literal fragments")
    if len(ids) != len(set(ids)):
        raise PanelError("duplicate manifest IDs")
    selected = selected if selected is not None else ids
    if (
        not selected
        or len(selected) != len(set(selected))
        or any(item not in ids for item in selected)
    ):
        raise PanelError("selection requires nonempty unique known exact case IDs")
    return [case for case in cases if case["id"] in selected]


def source_relevant(path):
    return (
        Path(path).suffix in (".rs", ".toml", ".lock", ".proto", ".c", ".h", ".cc", ".cpp")
        or path.startswith(("crates/", ".cargo/", "tests/ffi_oracles/"))
        or path in ("rust-toolchain", "rust-toolchain.toml")
    )


def dirty_sources(text):
    records = text.split("\0")
    if records[-1] != "":
        raise PanelError("truncated Git status output")
    records.pop()
    dirty = []
    while records:
        record = records.pop(0)
        if len(record) < 4 or record[2] != " ":
            raise PanelError("malformed Git status output")
        paths = [safe_relative(record[3:])]
        if "R" in record[:2] or "C" in record[:2]:
            if not records:
                raise PanelError("truncated Git rename output")
            paths.append(safe_relative(records.pop(0)))
        dirty.extend(path for path in paths if source_relevant(path))
    if dirty:
        raise PanelError(
            f"dirty source/config/fixture changes are not in the committed snapshot: {dirty}"
        )


def regular_source_file(root, name):
    path = root / name
    if any((root / parent).is_symlink() for parent in PurePosixPath(name).parents):
        raise PanelError(f"directory source links are refused: {name}")
    if path.is_symlink() or not path.is_file():
        raise PanelError(f"source is not a regular file: {name}")
    return path


def source_link_provenance(root, name, literal, regular_names):
    # The repository's links are direct, canonical relative file links. Link
    # chains and parent-relative/absolute paths remain deliberately unsupported.
    destination = (PurePosixPath(name).parent / safe_relative(literal)).as_posix()
    if destination not in regular_names:
        raise PanelError(f"source link target is not a committed regular file: {name}")
    target = regular_source_file(root, destination)
    return {
        "link_target": literal,
        "literal_sha256": hashlib.sha256(literal.encode()).hexdigest(),
        "resolved_target": destination,
        "target_sha256": sha256(target),
    }


def caller_inventory(root, listing):
    if not listing.endswith("\0"):
        raise PanelError("empty/truncated tracked source inventory")
    names = listing.split("\0")[:-1]
    for name in names:
        safe_relative(name)
    links = {name: os.readlink(root / name) for name in names if (root / name).is_symlink()}
    regular_names = set(names) - set(links)
    result = {}
    for name in names:
        if not source_relevant(name) and name not in links:
            continue
        path = root / name
        provenance = (
            source_link_provenance(root, name, links[name], regular_names)
            if name in links
            else None
        )
        if provenance is None:
            regular_source_file(root, name)
        info = path.lstat()
        result[name] = {
            "sha256": provenance["literal_sha256"] if provenance else sha256(path),
            "device": info.st_dev,
            "inode": info.st_ino,
            "size": info.st_size,
            "mtime_ns": info.st_mtime_ns,
        }
        if provenance:
            target = (root / provenance["resolved_target"]).stat()
            result[name].update(
                source_link=provenance,
                target_identity={
                    "device": target.st_dev,
                    "inode": target.st_ino,
                    "size": target.st_size,
                    "mtime_ns": target.st_mtime_ns,
                },
            )
    if not result:
        raise PanelError("source identity inventory is empty")
    return result


def file_manifest(root, source_links=None):
    result = {}
    for directory, dirs, files in os.walk(root):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            if path.is_symlink():
                raise PanelError(f"source snapshot contains a symlink: {path}")
            if path.is_file():
                result[path.relative_to(root).as_posix()] = {
                    "sha256": sha256(path),
                    "mode": stat.S_IMODE(path.stat().st_mode),
                }
            elif not path.is_dir():
                raise PanelError("source snapshot contains a special file")
    if not result:
        raise PanelError("source snapshot is empty")
    for name, provenance in (source_links or {}).items():
        if name not in result:
            raise PanelError("materialized source link is missing")
        result[name]["source_link"] = provenance
    return result


def extract_archive(archive, target):
    target.mkdir()
    seen = set()
    regular_names = set()
    links = {}
    total = 0
    with tarfile.open(archive, "r:") as stream:
        for member in stream:
            name = safe_relative(member.name.rstrip("/"))
            if name in seen or len(seen) >= 25000:
                raise PanelError("duplicate/oversized source archive inventory")
            seen.add(name)
            path = target / name
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            if member.issym():
                if len(member.linkname) > 4096:
                    raise PanelError("source link target exceeds literal limit")
                links[name] = member.linkname
                continue
            if not member.isfile() or member.size > 32 * 1024 * 1024:
                raise PanelError("archive hardlink or special/oversized member refused")
            regular_names.add(name)
            total += member.size
            if total > 256 * 1024 * 1024:
                raise PanelError("source archive exceeds byte limit")
            path.parent.mkdir(parents=True, exist_ok=True)
            with stream.extractfile(member) as source, path.open("xb") as destination:
                shutil.copyfileobj(source, destination)
            path.chmod(member.mode & 0o777)
    if any(parent.as_posix() in links for name in seen for parent in PurePosixPath(name).parents):
        raise PanelError("directory source links are refused")
    provenance = {
        name: source_link_provenance(target, name, literal, regular_names)
        for name, literal in links.items()
    }
    for name, record in provenance.items():
        source = target / record["resolved_target"]
        total += source.stat().st_size
        if total > 256 * 1024 * 1024:
            raise PanelError("materialized source archive exceeds byte limit")
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as original, path.open("xb") as materialized:
            shutil.copyfileobj(original, materialized)
        path.chmod(stat.S_IMODE(source.stat().st_mode))
    return provenance


def cache_inventory(root):
    result = {}
    for directory, dirs, files in os.walk(root):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise PanelError(f"cache symlink refused (cannot alias ordinary outputs): {path}")
            if not stat.S_ISREG(info.st_mode) and not stat.S_ISDIR(info.st_mode):
                raise PanelError(f"cache special file refused: {path}")
            result[path.relative_to(root).as_posix()] = (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_mode,
            )
    return result


def import_ownership_helper(path):
    spec = importlib.util.spec_from_file_location("mutation_panel_native_ownership", path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    for name in ("prepare_child_ownership", "settle_owned_children", "owned_children"):
        if not callable(getattr(helper, name, None)):
            raise PanelError(f"missing sibling ownership primitive: {name}")
    return helper


def atomic_receipt(path, receipt):
    staging = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", prefix=path.name + ".", suffix=".tmp", dir=path.parent, delete=False
        ) as stream:
            staging = Path(stream.name)
            json.dump(receipt, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        staging.replace(path)
    finally:
        if staging is not None:
            staging.unlink(missing_ok=True)


class Panel:
    def __init__(self, receipt, deadline, logs, helper, cleanup_mode=False):
        self.receipt = receipt
        self.deadline = deadline
        self.logs = logs
        self.helper = helper
        self.cleanup_mode = cleanup_mode

    def remaining(self, cap):
        if not self.cleanup_mode:
            check_interruption()
        remaining = min(cap, self.deadline - time.monotonic())
        if remaining <= 0:
            raise PanelError("total timeout exhausted")
        return remaining

    def run(self, argv, cwd, env, kind, cap=AUX_CAP):
        timeout = self.remaining(cap)
        entry = {
            "argv": [str(item) for item in argv],
            "cwd": str(cwd),
            "kind": kind,
            "cleanup_complete": False,
            "status": "running",
            "ownership": "linux-subreaper-pidfd",
        }
        self.receipt["commands"].append(entry)
        log = self.logs / f"{len(self.receipt['commands']):03}-{kind}.log"
        entry["log_path"] = str(log)
        started = time.monotonic()
        process = None
        timed_out = False
        try:
            self.helper.prepare_child_ownership()
            with log.open("wb") as output:
                process = subprocess.Popen(
                    entry["argv"],
                    cwd=cwd,
                    env=env,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                entry["pid"] = process.pid
                try:
                    # A signal handler must never raise between child creation
                    # and this guard. Observe its request only after ownership
                    # is registered, then retire the child in the same finally.
                    deadline = started + timeout
                    while True:
                        if not self.cleanup_mode:
                            check_interruption()
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            timed_out = True
                            break
                        try:
                            process.wait(timeout=min(0.1, remaining))
                            break
                        except subprocess.TimeoutExpired:
                            pass
                    if not self.cleanup_mode:
                        check_interruption()
                finally:
                    previous = {
                        signum: signal.signal(signum, signal.SIG_IGN)
                        for signum in (signal.SIGINT, signal.SIGTERM)
                    }
                    try:
                        killed, descendants, reaped = self.helper.settle_owned_children(process)
                        entry.update(
                            cleanup_complete=True,
                            root_killed=killed,
                            owned_descendants=descendants,
                            reaped_descendants=reaped,
                        )
                    finally:
                        for signum, handler in previous.items():
                            signal.signal(signum, handler)
            entry.update(status="timeout" if timed_out else "exited", returncode=process.returncode)
        except BaseException as error:
            entry["error"] = str(error)
            entry["status"] = "error"
            if process is None:
                entry["cleanup_complete"] = not self.helper.owned_children()
            raise
        finally:
            entry["duration_seconds"] = time.monotonic() - started
            if process is not None:
                entry["returncode"] = process.returncode
            if log.exists():
                entry.update(log_sha256=sha256(log), log_bytes=log.stat().st_size)
        if timed_out:
            raise PanelError(f"{kind} timeout after {timeout:.3f}s")
        if entry["owned_descendants"]:
            raise PanelError(
                f"{kind} left detached descendants (reaped): {entry['owned_descendants']}"
            )
        if entry["log_bytes"] > LOG_LIMIT:
            raise PanelError(f"{kind} output exceeded the complete-evidence byte limit")
        text = log.read_text(encoding="utf-8", errors="strict")
        entry["tail"] = text[-2000:]
        return entry, text

    def success(self, argv, cwd, env, kind, cap=AUX_CAP):
        entry, text = self.run(argv, cwd, env, kind, cap)
        if entry["returncode"] != 0:
            raise PanelError(
                f"{kind} failed with exit {entry['returncode']}: {entry.get('tail', '')}"
            )
        return text

    def donor_lock(self, cleanup=False):
        deadline = time.monotonic() + (5 if cleanup else self.remaining(AUX_CAP))

        class Lock:
            def __enter__(lock):
                lock.fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                try:
                    while True:
                        if time.monotonic() >= deadline:
                            raise PanelError("donor lock timeout")
                        try:
                            fcntl.flock(lock.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            return lock
                        except BlockingIOError:
                            time.sleep(0.02)
                except BaseException:
                    os.close(lock.fd)
                    raise

            def __exit__(lock, *unused):
                os.close(lock.fd)

        return Lock()

    def clone(self, source, target, cp, env):
        inventory = cache_inventory(source)
        target.mkdir()
        self.success(
            [cp, "--reflink=always", "-a", str(source) + "/.", str(target)],
            target.parent,
            env,
            "clone",
        )
        copied = cache_inventory(target)
        if set(copied) != set(inventory):
            raise PanelError("cache clone inventory mismatch")
        for name, info in inventory.items():
            if stat.S_ISREG(info[4]) and info[:2] == copied[name][:2]:
                raise PanelError("cache clone shares an inode with its donor")
        return inventory

    def build(self, case, source, target, env, cargo):
        self.success(
            [cargo, "clean", "--locked", "--offline", "-p", case["package"], "--profile", "dev"],
            source,
            env,
            "clean-package",
        )
        selector = (
            ["--lib"] if case["target"]["kind"] == "lib" else ["--test", case["target"]["name"]]
        )
        text = self.success(
            [
                cargo,
                "test",
                "--locked",
                "--offline",
                "--no-run",
                "--message-format=json",
                "-p",
                case["package"],
                *selector,
            ],
            source,
            env,
            "build",
            BUILD_CAP,
        )
        messages = [json.loads(line) for line in text.splitlines() if line.startswith("{")]
        if any(
            message.get("reason") == "compiler-message"
            and message.get("message", {}).get("level") == "error"
            for message in messages
        ):
            raise PanelError("Cargo reported a compiler error despite successful build exit")
        finished = [message for message in messages if message.get("reason") == "build-finished"]
        if len(finished) != 1 or finished[0].get("success") is not True:
            raise PanelError("build requires one successful Cargo build-finished record")
        artifacts = [
            message
            for message in messages
            if message.get("reason") == "compiler-artifact"
            and message.get("target", {}).get("name") == case["target"]["name"]
            and case["target"]["kind"] in message.get("target", {}).get("kind", [])
            and message.get("profile", {}).get("test") is True
            and message.get("executable")
        ]
        if len(artifacts) != 1 or artifacts[0].get("fresh") is not False:
            raise PanelError("build requires exactly one freshly compiled matching executable")
        artifact = Path(artifacts[0]["executable"])
        if (
            not artifact.is_absolute()
            or artifact.is_symlink()
            or not artifact.is_file()
            or not artifact.resolve().is_relative_to(target.resolve())
            or not os.access(artifact, os.X_OK)
        ):
            raise PanelError(
                "built executable must be a regular executable inside dedicated output"
            )
        return artifact.resolve()

    def test(self, artifact, name, source, env, panic=None):
        command_index = len(self.receipt["commands"])
        try:
            entry, text = self.run(
                [artifact, "--exact", name, "--test-threads=1", "--nocapture"],
                source,
                env,
                "test",
                TEST_CAP,
            )
        finally:
            if len(self.receipt["commands"]) > command_index:
                self.receipt["commands"][command_index]["test_id"] = name
        summaries = re.findall(
            r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
            r"(\d+) measured; (\d+) filtered out(?:; finished in [^\r\n]+)?$",
            text,
            re.MULTILINE,
        )
        if len(summaries) != 1:
            raise PanelError("test requires exactly one complete terminal summary")
        verdict, passed, failed, ignored, measured, filtered = summaries[0]
        counts = dict(
            zip(
                ("passed", "failed", "ignored", "measured", "filtered"),
                map(int, (passed, failed, ignored, measured, filtered)),
            )
        )
        entry["test_counts"] = counts
        result = {
            "id": name,
            "returncode": entry["returncode"],
            "counts": counts,
            "command_index": len(self.receipt["commands"]) - 1,
        }
        exact = re.escape(name)
        if counts["ignored"] or counts["measured"] or counts["passed"] + counts["failed"] != 1:
            raise PanelError("test selected zero/multiple/ignored cases")
        if (
            entry["returncode"] == 0
            and verdict == "ok"
            and counts["passed"] == 1
            and re.search(r"^test " + exact + r" \.\.\. ok$", text, re.MULTILINE)
        ):
            result["status"] = "passed"
            return result
        panic_location = (
            (
                r"^thread '"
                + exact
                + r"'(?: \(\d+\))? panicked at "
                + re.escape(panic["source"])
                + r":\d+:\d+:$"
            )
            if panic
            else None
        )
        if (
            panic
            and entry["returncode"] == 101
            and verdict == "FAILED"
            and counts["failed"] == 1
            and re.search(r"^test " + exact + r" \.\.\. (?:FAILED)?$", text, re.MULTILINE)
            and len(re.findall(panic_location, text, re.MULTILINE)) == 1
            and text.count("panicked at ") == 1
            and all(fragment in text for fragment in panic["fragments"])
        ):
            result.update(status="intended-assertion-failed", panic_verified=True)
            return result
        raise PanelError(
            f"test failed without the intended assertion evidence: {name}, exit={entry['returncode']}"
        )


def interrupt(signum, frame):
    # Raising asynchronously can lose a child created by Popen before its
    # returned handle is assigned. Poll the request only inside guarded work;
    # repeated handled signals cannot interrupt ownership retirement.
    global INTERRUPTED_SIGNAL
    if INTERRUPTED_SIGNAL is None:
        INTERRUPTED_SIGNAL = signum


def check_interruption():
    if INTERRUPTED_SIGNAL is not None:
        raise PanelError(f"interrupted by signal {INTERRUPTED_SIGNAL}")


def remove_ephemeral(path):
    def expired(signum, frame):
        raise PanelError("temporary-directory cleanup timeout")

    previous_handler = signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, EPHEMERAL_REMOVAL_CAP)
    try:
        shutil.rmtree(path)
    finally:
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        signal.signal(signal.SIGALRM, previous_handler)


def main(argv=None):
    global INTERRUPTED_SIGNAL
    INTERRUPTED_SIGNAL = None
    parser = PanelArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--case", action="append", dest="cases")
    parser.add_argument("--source-ref", default="HEAD")
    parser.add_argument("--seed-target", type=Path)
    parser.add_argument(
        "--timeout",
        type=float,
        default=240,
        help="finite positive total work budget; child cleanup has its own bounded backstop",
    )
    os.umask(0o077)
    started = time.monotonic()
    # Locate only the receipt/cache paths first. Invalidate a previous PASS
    # before the full parser can reject a malformed timeout/unknown option.
    preliminary = PanelArgumentParser(add_help=False, allow_abbrev=False)
    preliminary.add_argument("--output", type=Path)
    # A missing seed value is a full-parser error. Keep every supplied cache
    # path for output protection while still invalidating a known safe output.
    preliminary.add_argument("--seed-target", type=Path, action="append", nargs="?")
    try:
        paths, _ = preliminary.parse_known_args(argv)
        if paths.output is None:
            raise PanelError("--output is required")
    except PanelError as error:
        print(f"mutation-panel failed: {error}", file=sys.stderr)
        return 1
    known_donors = [path.resolve() for path in paths.seed_target or [] if path is not None]
    donor = known_donors[-1] if known_donors else None
    output = paths.output
    if (
        not output.is_absolute()
        or output.is_symlink()
        or output.resolve().is_relative_to(ROOT)
        or any(output.resolve().is_relative_to(path) for path in known_donors)
        or (output.exists() and (not output.is_file() or output.stat().st_nlink != 1))
    ):
        print(
            "--output must be an absolute regular path outside the caller checkout and donor; "
            "receipts must never replace source/cache files",
            file=sys.stderr,
        )
        return 1
    output = output.resolve()
    receipt = {
        "schema": "mutation-panel/v1",
        "status": "running",
        "selected_ids": [],
        "executed_ids": [],
        "cases": [],
        "commands": [],
        "cleanup": {"complete": False},
        "source_mode": "committed-archive",
        "requested_ref": None,
        "timeout_seconds": None,
    }
    scratch = None
    helper = None
    panel = None
    caller = None
    donor_before = None
    listing = None
    env = None
    git = None
    completed = False
    inputs = {}
    receipt_write_failed = False
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        atomic_receipt(output, receipt)
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, interrupt)
        args = parser.parse_args(argv)
        donor = args.seed_target.resolve() if args.seed_target else None
        receipt.update(
            requested_ref=args.source_ref,
            timeout_seconds=args.timeout if math.isfinite(args.timeout) else None,
        )
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise PanelError("timeout must be finite and positive")
        if not args.source_ref:
            raise PanelError("source ref must be nonempty")
        if sys.platform != "linux":
            raise PanelError("Linux subreaper/pidfd child ownership is mandatory")
        cases = load_manifest(ROOT / "tests/mutation-panel.json", args.cases)
        receipt.update(
            selected_ids=[case["id"] for case in cases],
            runner_sha256=sha256(Path(__file__).resolve()),
            manifest_sha256=sha256(ROOT / "tests/mutation-panel.json"),
            helper_sha256=sha256(ROOT / "scripts/run-native-contracts.py"),
        )
        inputs = {
            Path(__file__).resolve(): receipt["runner_sha256"],
            ROOT / "tests/mutation-panel.json": receipt["manifest_sha256"],
            ROOT / "scripts/run-native-contracts.py": receipt["helper_sha256"],
        }
        helper = import_ownership_helper(ROOT / "scripts/run-native-contracts.py")
        tools = {}
        for name in ("git", "rustup", *(["cp"] if donor else [])):
            path = shutil.which(name)
            if not path:
                raise PanelError(f"mandatory tool missing: {name}")
            tools[name] = str(Path(path).absolute())
        receipt["tools"] = {
            name: {"path": path, "sha256": sha256(Path(path))} for name, path in tools.items()
        }
        if donor:
            if (
                args.seed_target.is_symlink()
                or not donor.is_dir()
                or ROOT.is_relative_to(donor)
                or (donor.is_relative_to(ROOT) and donor != ROOT / "target")
            ):
                raise PanelError("donor must be a separate cache or the caller ignored target root")
        logs = Path(tempfile.mkdtemp(prefix=output.name + ".logs-", dir=output.parent))
        receipt["retained_logs"] = str(logs)
        panel = Panel(receipt, started + args.timeout, logs, helper)
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("CARGO", "RUST", "PKCS11_", "RETAINED_ORACLE_", "EXACT_ORACLE_"))
            and key
            not in ("LD_PRELOAD", "LD_LIBRARY_PATH", "CC", "CXX", "AR", "CFLAGS", "CXXFLAGS")
        }
        env.update(LC_ALL="C", LANG="C", RUSTUP_AUTO_INSTALL="0")
        git = tools["git"]
        if (
            Path(
                panel.success([git, "rev-parse", "--show-toplevel"], ROOT, env, "git").strip()
            ).resolve()
            != ROOT
        ):
            raise PanelError("caller checkout must be the Git repository root")
        commit = panel.success(
            [git, "rev-parse", "--verify", "--end-of-options", args.source_ref + "^{commit}"],
            ROOT,
            env,
            "git",
        ).strip()
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
            raise PanelError("Git did not resolve one exact commit")
        dirty_sources(
            panel.success(
                [git, "status", "--porcelain=v1", "-z", "--untracked-files=all"], ROOT, env, "git"
            )
        )
        listing = panel.success([git, "ls-files", "-z", "--cached"], ROOT, env, "git")
        caller = caller_inventory(ROOT, listing)
        receipt["caller_sources"] = caller
        scratch = Path(tempfile.mkdtemp(prefix="pkcs11-mutation-panel-", dir="/tmp")).resolve()
        receipt["ephemeral_root"] = str(scratch)
        if (
            scratch.is_relative_to(ROOT)
            or ROOT.is_relative_to(scratch)
            or (donor and (scratch.is_relative_to(donor) or donor.is_relative_to(scratch)))
        ):
            raise PanelError("temporary variant/source/donor roots overlap")
        env["TMPDIR"] = str(scratch)
        archive = scratch / "source.tar"
        panel.success(
            [git, "archive", "--format=tar", "--output=" + str(archive), commit],
            ROOT,
            env,
            "archive",
        )
        pristine = scratch / "pristine"
        source_links = extract_archive(archive, pristine)
        sources = file_manifest(pristine, source_links)
        receipt["source"] = {
            "commit": commit,
            "archive_sha256": sha256(archive),
            "manifest_sha256": canonical_hash(sources),
            "files": sources,
            "links": source_links,
        }
        channel = tomllib.loads((pristine / "rust-toolchain.toml").read_text())["toolchain"][
            "channel"
        ]
        if not isinstance(channel, str) or not re.fullmatch(r"\d+\.\d+\.\d+", channel):
            raise PanelError("snapshot must pin an exact installed Rust version")
        for name in ("cargo", "rustc"):
            raw = panel.success(
                [tools["rustup"], "which", "--toolchain", channel, name], ROOT, env, "toolchain"
            ).strip()
            path = Path(raw)
            if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
                raise PanelError(f"invalid/missing pinned {name} executable")
            tools[name] = str(path.resolve())
            version = panel.success([tools[name], "--version"], ROOT, env, "toolchain").strip()
            if not re.match(re.escape(name + " " + channel) + r"(?:\s|$)", version):
                raise PanelError(f"pinned {name} version mismatch: {version}")
            receipt["tools"][name] = {
                "path": tools[name],
                "sha256": sha256(Path(tools[name])),
                "version": version,
            }
        env.update(
            RUSTC=tools["rustc"],
            PATH=str(Path(tools["rustc"]).parent) + os.pathsep + env.get("PATH", ""),
        )
        seed = None
        if donor:
            seed = scratch / "cache-seed"
            with panel.donor_lock():
                donor_before = panel.clone(donor, seed, tools["cp"], env)
                if cache_inventory(donor) != donor_before:
                    raise PanelError("donor cache changed during capture")
            info = donor.stat()
            receipt["donor"] = {
                "path": str(donor),
                "device": info.st_dev,
                "inode": info.st_ino,
                "metadata_sha256": canonical_hash(donor_before),
                "unchanged": False,
            }
        for case in cases:
            panel.remaining(AUX_CAP)
            result = {
                "id": case["id"],
                "status": "error",
                "variants": [],
                "mutation": {
                    "source": case["source"],
                    "before_sha256": hashlib.sha256(case["before"].encode()).hexdigest(),
                    "after_sha256": hashlib.sha256(case["after"].encode()).hexdigest(),
                },
                "panic_contract": case["panic"],
            }
            receipt["cases"].append(result)
            original = (pristine / case["source"]).read_bytes()
            if original.count(case["before"].encode()) != 1:
                raise PanelError(f"mutation anchor must occur exactly once: {case['id']}")
            if case["panic"]["source"] not in sources:
                raise PanelError("panic assertion source is absent from snapshot")
            primary = None
            for variant in ("baseline", "mutant"):
                base = scratch / case["id"] / variant
                base.mkdir(parents=True)
                source = base / "source"
                shutil.copytree(pristine, source)
                if variant == "mutant":
                    (source / case["source"]).write_bytes(
                        original.replace(case["before"].encode(), case["after"].encode(), 1)
                    )
                expected_sources = file_manifest(source, source_links)
                target = base / "target"
                variant_result = {
                    "variant": variant,
                    "source_path": str(source),
                    "target_path": str(target),
                    "removed": False,
                    "tests": [],
                    "source_manifest_sha256": canonical_hash(expected_sources),
                    "mutation_source_sha256": sha256(source / case["source"]),
                }
                result["variants"].append(variant_result)
                if seed:
                    panel.clone(seed, target, tools["cp"], env)
                else:
                    target.mkdir()
                variant_env = dict(
                    env,
                    CARGO_TARGET_DIR=str(target),
                    CARGO_BUILD_BUILD_DIR=str(target / "build"),
                    CARGO_BUILD_JOBS="2",
                )
                artifact = panel.build(case, source, target, variant_env, tools["cargo"])
                artifact_hash = sha256(artifact)
                variant_result["artifact"] = {
                    "path": str(artifact),
                    "sha256": artifact_hash,
                    "ephemeral": True,
                }
                inventory = panel.success(
                    [artifact, "--list", "--format", "terse"],
                    source,
                    variant_env,
                    "inventory",
                    TEST_CAP,
                )
                listed = re.findall(r"^(.+): test$", inventory, re.MULTILINE)
                variant_result["listed_tests"] = listed
                if len(listed) != len(set(listed)) or any(
                    listed.count(case[key]) != 1 for key in ("primary", "control")
                ):
                    raise PanelError(
                        "exact primary/control test inventory is missing or duplicated"
                    )
                command_index = len(receipt["commands"])
                try:
                    primary = panel.test(
                        artifact,
                        case["primary"],
                        source,
                        variant_env,
                        case["panic"] if variant == "mutant" else None,
                    )
                finally:
                    if (
                        variant == "mutant"
                        and len(receipt["commands"]) > command_index
                        and receipt["commands"][command_index].get("pid")
                    ):
                        receipt["executed_ids"].append(case["id"])
                variant_result["tests"].append(primary)
                control = panel.test(artifact, case["control"], source, variant_env)
                variant_result["tests"].append(control)
                if (
                    sha256(artifact) != artifact_hash
                    or file_manifest(source, source_links) != expected_sources
                ):
                    raise PanelError("variant source or compiled artifact changed during execution")
            result["status"] = (
                "killed" if primary["status"] == "intended-assertion-failed" else "survived"
            )
            if result["status"] == "survived":
                raise PanelError(f"mutant survived its primary test: {case['id']}")
        if receipt["executed_ids"] != receipt["selected_ids"] or not receipt["executed_ids"]:
            raise PanelError("panel did not execute every selected mutation")
        completed = True
    except BaseException as error:
        completed = False
        receipt["error"] = str(error)
        print(f"mutation-panel failed: {error}", file=sys.stderr)
    finally:
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, signal.SIG_IGN)
        if INTERRUPTED_SIGNAL is not None:
            completed = False
            receipt.setdefault("error", f"interrupted by signal {INTERRUPTED_SIGNAL}")
        cleanup_errors = []
        if inputs:
            try:
                receipt["inputs_unchanged"] = all(
                    path.is_file() and sha256(path) == expected for path, expected in inputs.items()
                )
                if not receipt["inputs_unchanged"]:
                    raise PanelError("runner/manifest/ownership helper changed during panel")
            except BaseException as error:
                cleanup_errors.append(str(error))
        if caller is not None:
            receipt["caller_unchanged"] = False
            try:
                cleanup_panel = Panel(
                    receipt, time.monotonic() + 5, panel.logs, helper, cleanup_mode=True
                )
                dirty_sources(
                    cleanup_panel.success(
                        [git, "status", "--porcelain=v1", "-z", "--untracked-files=all"],
                        ROOT,
                        env,
                        "git",
                        5,
                    )
                )
                if caller_inventory(ROOT, listing) != caller:
                    raise PanelError("caller source identity changed during panel")
                receipt["caller_unchanged"] = True
            except BaseException as error:
                cleanup_errors.append(str(error))
        if donor_before is not None:
            try:
                with panel.donor_lock(cleanup=True):
                    unchanged = cache_inventory(donor) == donor_before
                receipt.setdefault("donor", {})["unchanged"] = unchanged
                if not unchanged:
                    raise PanelError("ordinary donor identity changed during panel")
            except BaseException as error:
                cleanup_errors.append(str(error))
        children_gone = helper is None or not helper.owned_children()
        removal = {
            "budget_seconds": EPHEMERAL_REMOVAL_CAP,
            "duration_seconds": 0.0,
            "attempted": False,
            "status": "not-created",
        }
        if scratch is not None:
            removal_started = time.monotonic()
            removal["status"] = "failed"
            try:
                if not children_gone:
                    raise PanelError("owned children remain; preserving their temporary files")
                removal["attempted"] = True
                remove_ephemeral(scratch)
                removal["status"] = "removed"
            except BaseException as error:
                cleanup_errors.append(f"cleanup: {error}")
            finally:
                removal["duration_seconds"] = time.monotonic() - removal_started
        for case in receipt["cases"]:
            for variant in case["variants"]:
                variant["removed"] = (
                    not Path(variant["source_path"]).exists()
                    and not Path(variant["target_path"]).exists()
                )
        complete = (
            children_gone
            and not cleanup_errors
            and (scratch is None or not scratch.exists())
            and all(command["cleanup_complete"] for command in receipt["commands"])
        )
        receipt["cleanup"] = {
            "complete": complete,
            "errors": cleanup_errors,
            "ephemeral_root_removed": scratch is None or not scratch.exists(),
            "ephemeral_removal": removal,
        }
        if cleanup_errors:
            receipt["error"] = "; ".join([receipt.get("error", ""), *cleanup_errors]).strip("; ")
        receipt["status"] = "passed" if completed and complete else "failed"
        receipt["duration_seconds"] = time.monotonic() - started
        receipt["build_seconds"] = sum(
            command["duration_seconds"]
            for command in receipt["commands"]
            if command["kind"] == "build"
        )
        receipt["test_seconds"] = sum(
            command["duration_seconds"]
            for command in receipt["commands"]
            if command["kind"] == "test"
        )
        receipt["counts"] = {
            status: sum(case["status"] == status for case in receipt["cases"])
            for status in ("killed", "survived", "error")
        }
        try:
            atomic_receipt(output, receipt)
        except BaseException as error:
            print(f"mutation-panel receipt write failed: {error}", file=sys.stderr)
            receipt_write_failed = True
    if receipt_write_failed:
        return 1
    print(
        f"mutation-panel: {receipt['status']} ({receipt['counts']['killed']}/{len(receipt['selected_ids'])})"
    )
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Stubbed regression tests for the perf harness drivers (Q09 cold-start).

The cold-start storm (``scripts/perf/cold_start_storm.sh``) normally drives
Docker fixtures. These tests execute the staged script bytes against stubbed
external commands (``docker``, ``sleep``, ``top``, ``pkcs11-tool``,
``date``) in an isolated PATH, with a fake /proc tree for daemon RSS
reads. ``date`` is stubbed (not farmed) because the host uutils 0.10.0
implementation reads ``%s`` and ``%N`` separately and goes backward
~0.6% of the time, which would poison wall measurements at random; the
stub takes a single clock read per call (see ``DATE_STUB``).

Every run executes under an external session bound: the script starts in
a fresh session, the test reaps it with a timeout, and any expiry kills
the whole session. After each run the test scans /proc for survivors of
the run's session (a group scan would miss the script's per-job groups),
so leaked samplers/workers fail the test instead of lingering on the
machine.

No Docker daemon, provider, or container is touched. Q10 extends this module
with the soak-driver suite reusing the same harness.
"""

from __future__ import annotations

import csv
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[2]
COLD_START_SRC = ROOT / "scripts" / "perf" / "cold_start_storm.sh"
SOAK_SRC = ROOT / "scripts" / "perf" / "soak.sh"

BASH = shutil.which("bash") or "bash"

#: External wall bound for a script run. The repaired scripts must always
#: terminate well inside it; the unrepaired cold-start script hangs in it.
RUN_BOUND_SECS = 25
#: Tighter bound for usage/setup rejections, which must fail fast.
REJECT_BOUND_SECS = 8

DAEMON_PID = "999999999"

SLEEP_STUB = """#!/usr/bin/env python3
import os
import sys
import time

if len(sys.argv) != 2:
    sys.exit(2)
arg = sys.argv[1]
if os.environ.get("STUB_SLEEP_HANG_ON", "") == arg:
    time.sleep(600)
try:
    delay = float(arg)
except ValueError:
    sys.exit(2)
if delay < 0:
    sys.exit(2)
if os.environ.get("STUB_SLEEP_NOCAP") == "1":
    time.sleep(delay)
else:
    time.sleep(min(delay, 0.05))
"""

TOP_STUB = """#!/usr/bin/env python3
import os
import sys

if os.environ.get("STUB_TOP_FAIL") == "1":
    sys.exit(1)
pid = os.environ.get("STUB_DAEMON_PID", "999999999")
if pid not in sys.argv:
    sys.exit(3)
cpu = os.environ.get("STUB_TOP_CPU", "12.5")
# Field layout mirrors `top -b -n 1`: $1 is the PID, $9 is %CPU.
print(f"{pid} root 20 0 100000 50000 10000 S {cpu} 4.2 0:00.01 top")
"""

PKCS11_TOOL_STUB = """#!/usr/bin/env python3
import os
import signal
import sys
import time


def marker_path(name):
    marker_dir = os.environ.get("STUB_MARKER_DIR", "")
    if not marker_dir:
        return None
    return os.path.join(marker_dir, name)


def touch(path):
    if path is not None:
        with open(path, "w"):
            pass


def wait_for(path, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path is not None and os.path.exists(path):
            return True
        time.sleep(0.02)
    return path is not None and os.path.exists(path)


def finish(code):
    # Terminate with a real exit status. The stub CLI reaps the shim
    # and reports what waitpid observed — never a file the shim wrote
    # about itself, which a crash-after-report would poison.
    sys.exit(code)


mode = os.environ.get("STUB_PKCS11_MODE", "ok")
index = os.environ.get("COLD_START_SHIM_INDEX", "")
touch(marker_path(f"entered-{index}") if index else None)
pattern = os.environ.get("STUB_SOAK_OP_PATTERN", "")
if pattern:
    # Q10 mixed-outcome workload: cycle per-invocation outcomes so one
    # run preserves every category (timeout sleeps until the worker's
    # per-op timeout kills it; unknown exits 127 like broken tooling).
    entries = [item.strip() for item in pattern.split(",") if item.strip()]
    if not entries:
        finish(2)
    pattern_tmp = os.environ.get("STUB_CONTAINER_TMP", "")
    pattern_idx = os.path.join(pattern_tmp, "op-pattern.idx")
    try:
        with open(pattern_idx) as handle:
            call_no = int(handle.read().strip() or "0")
    except (OSError, ValueError):
        call_no = 0
    try:
        with open(pattern_idx, "w") as handle:
            handle.write(f"{call_no + 1}\\n")
    except OSError:
        finish(2)
    entry = entries[call_no % len(entries)]
    if entry == "ok":
        finish(0)
    if entry == "error":
        finish(1)
    if entry == "timeout":
        time.sleep(600)
    if entry == "unknown":
        finish(127)
    finish(2)
if mode == "hang":
    time.sleep(600)
elif mode == "ignore-term-hang":
    # Orphan control: survive TERM so only KILL (or a descendant-aware
    # escalation) can stop this shim.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(600)
elif mode == "fail":
    finish(1)
elif mode == "fail-index":
    # Duration ordering comes from injected stub-clock walls, never
    # from scheduling margins: just fail.
    if index == os.environ.get("STUB_PKCS11_FAIL_INDEX"):
        finish(1)
elif mode == "fail-when-daemon-gone":
    # Deterministic daemon-death control: wait for the status file to
    # disappear, then wait for the test's release marker (written once
    # post-deletion sampler evidence has landed), then fail.
    status = os.environ.get("STUB_DAEMON_STATUS_PATH", "")
    deadline = time.monotonic() + 30
    while status and os.path.exists(status) and time.monotonic() < deadline:
        time.sleep(0.02)
    if not status or os.path.exists(status):
        finish(0)
    release = os.environ.get("STUB_RELEASE_PATH", "")
    if release and not wait_for(release):
        finish(0)
    finish(1)
elif mode == "wait-release":
    # Deterministic mid-run window: hold the workload until the test
    # releases it, so exactly-once interventions (tamper) land before
    # the run can finish. A missing release path fails closed rather
    # than silently racing the run.
    release = os.environ.get("STUB_RELEASE_PATH", "")
    if not release:
        finish(2)
    wait_for(release)
elif mode == "boom":
    # Round 4 finding 1: report success through the legacy channel and
    # then die without it. A file-trusting oracle reports this shim
    # successful; a real-exit oracle reports its true exit status.
    tmp = os.environ.get("STUB_CONTAINER_TMP", "")
    if tmp and index:
        with open(os.path.join(tmp, f"shim-{index}.code"), "w") as handle:
            handle.write("0")
    raise RuntimeError("boom-after-report")
elif mode != "ok":
    finish(2)
finish(0)
"""

DATE_STUB = """#!/usr/bin/env python3
# Correct-by-construction `date` for the formats the harness uses. The
# host uutils 0.10.0 `date` reads %s and %N separately and goes backward
# ~0.6% of the time, which would poison wall measurements at random;
# this stub takes a single clock read per call. Unknown formats fail
# closed so the suite pins the script's date usage.
import fcntl
import os
import sys
import time

if len(sys.argv) != 2:
    sys.exit(2)
fmt = sys.argv[1]
if fmt not in ("+%s%6N", "+%s"):
    sys.exit(2)
fail_caller = os.environ.get("STUB_DATE_FAIL_CALLER", "")
caller = os.environ.get("COLD_START_CLOCK_CALLER", "")
if fail_caller and caller == fail_caller:
    sys.exit(3)
if os.environ.get("STUB_DATE_MODE") == "fixed" and caller in ("worker-t0", "worker-t1"):
    # Deterministic injected durations: a pure function of the caller
    # key (phase + worker index), so walls are exact regardless of
    # scheduling. Non-worker callers (storm boundaries, sampler) and
    # unlisted indices stay on the realtime path / fail closed.
    walls = {}
    for item in os.environ.get("STUB_DATE_FIXED_WALLS", "").split(","):
        key, sep, value = item.partition(":")
        if sep and key.strip().isdigit() and value.strip().isdigit():
            walls[key.strip()] = int(value.strip())
    index = os.environ.get("COLD_START_SHIM_INDEX", "")
    if index not in walls:
        sys.exit(2)
    base = 1792000000000000
    now_us = base if caller == "worker-t0" else base + walls[index]
elif os.environ.get("STUB_DATE_MODE") == "backward":
    # Deterministic stepped clock: every call returns 2 s less than the
    # previous one (atomic across parallel callers), so every measured
    # wall is negative and every row is malformed.
    state_dir = os.environ.get("STUB_CONTAINER_TMP", "/tmp")
    state_path = os.path.join(state_dir, "stub-date-state")
    base = 1792000000000000
    with open(state_path, "a+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        handle.seek(0)
        counter = int(handle.read().strip() or 0)
        handle.seek(0)
        handle.truncate()
        handle.write(str(counter + 1))
    now_us = base - counter * 2000000
else:
    now_us = time.clock_gettime_ns(time.CLOCK_REALTIME) // 1000
if fmt == "+%s%6N":
    print(f"{now_us // 1000000}{now_us % 1000000:06d}")
else:
    print(f"{now_us // 1000000}")
"""

DOCKER_STUB = """#!/usr/bin/env python3
import json
import os
import signal
import subprocess
import sys
import time


def fail(msg):
    sys.stderr.write(f"stub-docker: {msg}\\n")
    return 1


def main(argv):
    if not argv:
        return fail("no arguments")
    if argv[0] == "inspect":
        return do_inspect(argv[1:])
    if argv[0] == "run":
        return do_run(argv[1:])
    if argv[0] == "rm":
        return do_rm(argv[1:])
    if argv[0] == "stop":
        return do_soak_stop(argv[1:])
    if argv[0] == "cp":
        return do_soak_cp(argv[1:])
    if argv[0] == "exec":
        return do_exec(argv[1:], kind="docker")
    if argv[0] != "compose":
        return fail(f"unexpected docker subcommand: {argv[0]}")
    rest = argv[1:]
    if len(rest) >= 2 and rest[0] == "-f":
        rest = rest[2:]
    if len(rest) >= 2 and rest[0] == "--profile":
        rest = rest[2:]
    if not rest:
        return fail("empty compose command")
    if rest[0] == "up":
        if os.environ.get("STUB_COMPOSE_UP_FAIL") == "1":
            sys.stderr.write("stub-docker: cannot reach the daemon\\n")
            return 1
        if os.environ.get("STUB_COMPOSE_UP_HANG") == "1":
            import time

            time.sleep(600)
        return 0
    if rest[0] == "exec":
        # Q10 legacy (shared stub): Q09 execs only into its owned run
        # container via plain `docker exec`.
        return do_exec(rest[1:], kind="compose")
    return fail(f"unexpected compose subcommand: {rest[0]}")


SHELL_INSPECT_FORMAT = (
    "{{println .Config.Image}}{{range .Config.Env}}{{println .}}{{end}}"
)
LABEL_INSPECT_FORMAT = '{{index .Config.Labels "coldstart-run-id"}}'
SOAK_LABEL_INSPECT_FORMAT = '{{index .Config.Labels "soak-run-id"}}'
SHELL_IMAGE = "stub-shell-image:latest"
SHELL_ENV = (
    ("PKCS11_PROXY_ENDPOINT", "http://daemon:7512"),
    ("PKCS11_PROXY_CONNECT_TIMEOUT", "5"),
    ("RUST_LOG", "pkcs11_proxy_ng_shim=warn"),
    ("DAEMON_HOST", "daemon"),
    ("DAEMON_PORT", "7512"),
)


def run_container_name():
    try:
        with open(
            os.path.join(os.environ.get("STUB_CONTAINER_TMP", ""), "run-manifest.log")
        ) as handle:
            first = handle.readline().split()
    except OSError:
        return None
    return first[0] if first else None


def do_inspect(args):
    if len(args) != 3 or args[0] != "--format":
        return fail(f"unexpected inspect shape: {args!r}")
    fmt, name = args[1], args[2]
    if fmt == "{{.State.Pid}}" and name == "consumer-matrix-daemon":
        if os.environ.get("STUB_INSPECT_FAIL") == "1":
            return 1
        output = os.environ.get(
            "STUB_INSPECT_OUTPUT",
            os.environ.get("STUB_DAEMON_PID", "999999999"),
        )
        sys.stdout.write(output + "\\n")
        return 0
    if fmt == "{{.Image}}" and name == "consumer-matrix-daemon":
        if os.environ.get("STUB_IMAGE_INSPECT_FAIL") == "1":
            sys.stderr.write("stub-docker: image inspect refused\\n")
            return 1
        if os.environ.get("STUB_IMAGE_INSPECT_HANG") == "1":
            time.sleep(600)
        sys.stdout.write(os.environ.get("STUB_DAEMON_IMAGE_ID", "sha256:stubdaemon0") + "\\n")
        return 0
    if fmt == SHELL_INSPECT_FORMAT and name == "consumer-matrix-shell":
        if os.environ.get("STUB_SHELL_INSPECT_FAIL") == "1":
            sys.stderr.write("stub-docker: shell inspect refused\\n")
            return 1
        output = os.environ.get("STUB_SHELL_INSPECT_OUTPUT")
        if output is None:
            output = SHELL_IMAGE + "\\n" + "\\n".join(f"{k}={v}" for k, v in SHELL_ENV)
        sys.stdout.write(output if output.endswith("\\n") else output + "\\n")
        return 0
    if fmt in (LABEL_INSPECT_FORMAT, SOAK_LABEL_INSPECT_FORMAT):
        # Reconcile identity check: verifiable ownership, or nothing.
        # Every dispatch is evidenced for barrier-controlled tests.
        # The label key selects the registry (coldstart vs soak).
        label_tmp = os.environ.get("STUB_CONTAINER_TMP", "")
        if label_tmp:
            with open(os.path.join(label_tmp, "inspect-manifest.log"), "a") as handle:
                handle.write(f"{name}\\n")
        if fmt == LABEL_INSPECT_FORMAT:
            owned = name == run_container_name()
        else:
            owned = name in soak_worker_names()
        if not owned:
            sys.stderr.write(f"error: no such object: {name}\\n")
            return 1
        fail_message = os.environ.get("STUB_RECONCILE_INSPECT_FAIL")
        if fail_message is not None:
            sys.stderr.write(f"stub-docker: {fail_message}\\n")
            return 1
        if os.environ.get("STUB_RECONCILE_INSPECT_HANG") == "1":
            time.sleep(600)
        if os.environ.get("STUB_RUN_LABEL_MISMATCH") == "1":
            # Real docker prints an empty line for a missing label key.
            print()
            return 0
        print(name)
        return 0
    return fail(f"unexpected inspect target: {args!r}")


def do_run(args):
    # Strict shape pins the script's run-container construction; the
    # recorded manifest pins its ownership (name, network, image,
    # ownership label, env). The ownership label selects the Q09
    # registry (coldstart-run-id) or the Q10 soak registry
    # (soak-run-id); each has its own creation-fault seams.
    if os.environ.get("STUB_DOCKER_RUN_FAIL") == "1":
        sys.stderr.write("stub-docker: cannot create run container\\n")
        return 1
    if os.environ.get("STUB_SOAK_RUN_FAIL") == "1":
        sys.stderr.write("stub-docker: cannot create soak worker\\n")
        return 1
    tmp = os.environ.get("STUB_CONTAINER_TMP", "")
    if not tmp:
        return fail("STUB_CONTAINER_TMP is not set")
    detach = False
    auto_remove = False
    name = None
    network = None
    label = None
    env = []
    rest = list(args)
    while rest and rest[0].startswith("-"):
        flag = rest.pop(0)
        if flag == "-d":
            detach = True
        elif flag == "--rm":
            auto_remove = True
        elif flag in ("--name", "--network", "--label", "-e"):
            if not rest:
                return fail(f"unexpected run shape: {args!r}")
            value = rest.pop(0)
            if flag == "--name":
                name = value
            elif flag == "--network":
                network = value
            elif flag == "--label":
                label = value
            else:
                key, sep, _ = value.partition("=")
                if not sep or not key:
                    return fail(f"malformed run env: {value!r}")
                env.append(value)
        else:
            return fail(f"unexpected run flag: {flag!r}")
    if not detach or not name or not network:
        return fail(f"unexpected run shape: {args!r}")
    if label == f"coldstart-run-id={name}":
        manifest_name = "run-manifest.log"
        hang_var = "STUB_DOCKER_RUN_HANG"
        rest_ok = len(rest) == 3 and rest[1:] == ["sleep", "31536000"]
        if not auto_remove:
            return fail(f"unexpected run shape: {args!r}")
    elif label == f"soak-run-id={name}":
        manifest_name = "soakworker-manifest.log"
        hang_var = "STUB_SOAK_RUN_HANG"
        rest_ok = len(rest) == 3 and rest[1:] == ["sleep", "infinity"]
        # The soak worker must persist for retirement (stopped, then
        # copied, then removed): auto-remove would race the copy.
        if auto_remove:
            return fail(f"unexpected run shape: {args!r}")
    else:
        return fail(f"run container lacks its ownership label: {args!r}")
    if not rest_ok:
        return fail(f"unexpected run shape: {args!r}")
    image = rest[0]
    manifest = os.path.join(tmp, manifest_name)
    if os.path.exists(manifest):
        return fail("run container already created")
    with open(manifest, "w") as handle:
        handle.write(f"{name} {network} {image}\\n")
        handle.write(f"label {label}\\n")
        for entry in env:
            handle.write(f"{entry}\\n")
    if os.environ.get(hang_var) == "1":
        # Created-then-stalled: the daemon committed (manifested) but
        # the CLI never acknowledges.
        time.sleep(600)
    print("stub-run-container-id")
    return 0


def remove_shims(tmp):
    # Authoritative removal kills every spawned shim.
    try:
        with open(os.path.join(tmp, "exec-manifest.log")) as handle:
            pids = [int(line.split()[1]) for line in handle if len(line.split()) == 2]
    except (OSError, ValueError, IndexError):
        pids = []
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        live = False
        for pid in pids:
            try:
                os.kill(pid, 0)
                live = True
                break
            except OSError:
                pass
        if not live:
            break
        time.sleep(0.02)


def soak_worker_names():
    try:
        with open(
            os.path.join(os.environ.get("STUB_CONTAINER_TMP", ""), "soakworker-manifest.log")
        ) as handle:
            first = handle.readline().split()
    except OSError:
        return set()
    return {first[0]} if first else set()


def soak_worker_descendants(pid):
    # Live descendants of one PID (models the container's process
    # tree: removal stops everything inside, not just the recorded
    # worker top). Best-effort: races with exit return a subset.
    found = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return found
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat") as handle:
                content = handle.read()
        except OSError:
            continue
        rest = content.rsplit(") ", 1)
        if len(rest) != 2:
            continue
        fields = rest[1].split()
        if len(fields) >= 2 and fields[1] == str(pid):
            try:
                child = int(entry)
            except ValueError:
                continue
            found.append(child)
            found.extend(soak_worker_descendants(child))
    return found


def remove_soak_workers(tmp):
    # Authoritative removal stops the recorded soak worker and its live
    # tree, however it was reparented (mirrors remove_shims for the
    # soak registry, extended to the tree: `docker rm -f` stops every
    # container process, including grandchildren the host never owned).
    try:
        with open(os.path.join(tmp, "soakworker-manifest.log")) as handle:
            pids = [
                int(line.split()[1])
                for line in handle
                if line.startswith("worker ") and len(line.split()) == 2
            ]
    except (OSError, ValueError, IndexError):
        pids = []
    targets = list(pids)
    for pid in pids:
        targets.extend(soak_worker_descendants(pid))
    for pid in targets:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        live = False
        for pid in targets:
            try:
                os.kill(pid, 0)
                live = True
                break
            except OSError:
                pass
        if not live:
            break
        time.sleep(0.02)


def do_rm(args):
    if len(args) != 2 or args[0] != "-f":
        return fail(f"unexpected rm shape: {args!r}")
    name = args[1]
    tmp = os.environ.get("STUB_CONTAINER_TMP", "")
    if not tmp:
        return fail("STUB_CONTAINER_TMP is not set")
    # Model a cleanup CLI that has not reached its removal operation yet.
    # The owning harness must settle this hold; it never releases itself.
    if os.environ.get("STUB_DOCKER_RM_PRE_ENTRY_HOLD") == "1":
        time.sleep(600)
    # The attempt is evidence even when it fails or misses.
    manifest = os.path.join(tmp, "rm-manifest.log")
    with open(manifest, "a") as handle:
        handle.write(f"{name}\\n")
    with open(manifest) as handle:
        attempt = len(handle.read().split())
    if name != run_container_name() and name not in soak_worker_names():
        sys.stderr.write(f"stub-docker: refusing to remove foreign container {name}\\n")
        return 1
    if os.environ.get("STUB_DOCKER_RM_FAIL") == "1":
        sys.stderr.write("stub-docker: removal refused\\n")
        return 1
    hang = os.environ.get("STUB_DOCKER_RM_HANG", "")
    if hang == "always" or (hang == "once" and attempt == 1):
        time.sleep(600)
    # Real `docker rm -f` is idempotent: removing an already-removed
    # container succeeds, so every attempt ends here the same way.
    remove_shims(tmp)
    remove_soak_workers(tmp)
    print(name)
    return 0


def do_legacy_soak_result():
    # Q10 legacy result read: the unrepaired soak reads the fixed
    # /tmp/soak_result.txt without joining its detached worker.
    # STUB_SOAK_LEGACY_RESULT selects the served content: "fail20" (the
    # review's all-fail reproduction), "empty" (no work), "missing"
    # (read fails), "seeded" (a previous run's file, proving stale
    # consumption), "garbage" (unparseable). STUB_SOAK_RESULT_HANG
    # hangs the read itself, like the owned-result path.
    if os.environ.get("STUB_SOAK_RESULT_HANG") == "1":
        time.sleep(600)
    mode = os.environ.get("STUB_SOAK_LEGACY_RESULT", "fail20")
    tmp = os.environ.get("STUB_CONTAINER_TMP", "")
    if mode == "fail20":
        print("ok=0 fail=20")
        return 0
    if mode == "empty":
        print("ok=0 fail=0")
        return 0
    if mode == "missing":
        sys.stderr.write("cat: /tmp/soak_result.txt: No such file or directory\\n")
        return 1
    if mode == "seeded":
        try:
            with open(os.path.join(tmp, "soak_result.txt")) as handle:
                sys.stdout.write(handle.read())
        except OSError:
            return fail("seeded legacy result was never written")
        return 0
    if mode == "garbage":
        print("not-a-result")
        return 0
    return fail(f"unknown legacy result mode: {mode!r}")


def do_daemon_fd_count(payload):
    # Daemon open-FD read: `docker exec consumer-matrix-daemon sh -c
    # '<payload>' where the payload propagates the ls status
    # explicitly (an ls failure exits 1 instead of printing wc's
    # zero). Spelled without pipefail: the daemon image's sh is
    # BusyBox ash, which has no such option. Only this spelling is
    # accepted. STUB_SOAK_FD_FAIL fails the read;
    # STUB_SOAK_FD_SEQ serves a per-call sequence (repeating the last
    # value); otherwise STUB_SOAK_FD_COUNT or the documented default.
    if payload != (
        "out=$(ls /proc/1/fd 2>/dev/null) || exit 1; "
        'if [ -z "$out" ]; then echo 0; '
        # Doubled escapes: this source is itself a Python literal.
        'else printf "%s\\\\n" "$out" | wc -l; fi'
    ):
        return fail(f"unexpected daemon fd payload: {payload!r}")
    if os.environ.get("STUB_SOAK_FD_FAIL") == "1":
        sys.stderr.write("stub-docker: fd count refused\\n")
        return 1
    seq = os.environ.get("STUB_SOAK_FD_SEQ", "")
    if seq:
        tmp = os.environ.get("STUB_CONTAINER_TMP", "")
        values = [item.strip() for item in seq.split(",")]
        idx_path = os.path.join(tmp, "fd-seq.idx")
        try:
            with open(idx_path) as handle:
                idx = int(handle.read().strip() or "0")
        except (OSError, ValueError):
            idx = 0
        value = values[min(idx, len(values) - 1)]
        try:
            with open(idx_path, "w") as handle:
                handle.write(f"{idx + 1}\\n")
        except OSError:
            return fail("fd sequence counter unwritable")
        if value == "FAIL":
            sys.stderr.write("stub-docker: fd count refused\\n")
            return 1
        print(value)
        return 0
    print(os.environ.get("STUB_SOAK_FD_COUNT", "42"))
    return 0


def do_soak_worker_exec(command, extra_env):
    # Owned soak worker: provision the worker script/input from the
    # piped stdin, run the worker for real (reaping its real exit),
    # and serve the unique result file (faults via
    # STUB_SOAK_RESULT_MODE; unset serves the mapped file honestly).
    tmp = os.environ.get("STUB_CONTAINER_TMP", "")
    if command[:2] == ["sh", "-c"] and len(command) == 3:
        if command[2] == "cat > /tmp/soak_worker.sh":
            data = sys.stdin.buffer.read()
            if not data:
                return fail("worker provision got no bytes")
            with open(os.path.join(tmp, "soak_worker.sh"), "wb") as handle:
                handle.write(data)
            return 0
        if command[2] == "cat > /tmp/soak_in.bin":
            data = sys.stdin.buffer.read()
            if not data:
                return fail("input provision got no bytes")
            with open(os.path.join(tmp, "soak_in.bin"), "wb") as handle:
                handle.write(data)
            return 0
        return run_container_shell(command[2], extra_env)
    if (
        len(command) == 6
        and command[0] == "bash"
        and command[1] == "/tmp/soak_worker.sh"
    ):
        return run_soak_worker(command, extra_env)
    # No exec-cat result read: the retired worker's frozen result is
    # copied with `docker cp` (a live `cat` could not prove a frozen
    # population).
    return fail(f"unexpected soak worker exec: {command!r}")


def run_soak_worker(argv, extra_env):
    # Foreground worker fidelity (mirrors run_shim): the CLI blocks,
    # records the spawn for authoritative removal, and reports the
    # REAL reaped exit status. Container paths map to the shared tmp
    # (argv directly; the script's internal paths via SOAK_CONTAINER_TMP).
    tmp = os.environ.get("STUB_CONTAINER_TMP", "")
    mapped = [
        item.replace("/tmp/", tmp + "/", 1) if item.startswith("/tmp/") else item
        for item in argv
    ]
    worker_env = dict(extra_env)
    worker_env["SOAK_CONTAINER_TMP"] = tmp
    # A real container carries its creation-time -e env into every
    # exec; the stub replays the recorded env lines the same way
    # (explicit exec -e wins, like real docker).
    try:
        with open(os.path.join(tmp, "soakworker-manifest.log")) as handle:
            manifest_lines = handle.read().splitlines()
    except OSError:
        manifest_lines = []
    for line in manifest_lines[2:]:
        if line.startswith("worker ") or line.startswith("label "):
            continue
        key, sep, value = line.partition("=")
        if sep and key:
            worker_env.setdefault(key, value)
    worker_pid = spawn_shim(mapped, worker_env)
    if worker_pid is None:
        return 127
    if tmp:
        with open(os.path.join(tmp, "soakworker-manifest.log"), "a") as handle:
            handle.write(f"worker {worker_pid}\\n")
    _, status = os.waitpid(worker_pid, 0)
    if os.WIFEXITED(status):
        code = os.WEXITSTATUS(status)
    elif os.WIFSIGNALED(status):
        code = 128 + os.WTERMSIG(status)
    else:
        code = 127
    if tmp:
        with open(os.path.join(tmp, "soakworker-exits.log"), "a") as handle:
            handle.write(f"{worker_pid} {code}\\n")
    return code


def do_soak_stop(args):
    # Bounded worker retirement: `docker stop -t SECS RUN` freezes
    # the owned worker (TERM, grace, KILL inside the runtime) while
    # retaining its result filesystem for the copy that follows.
    # STUB_DOCKER_STOP_FAIL faults the stop; STUB_DOCKER_STOP_HANG
    # hangs the CLI past the harness bound.
    if len(args) != 3 or args[0] != "-t":
        return fail(f"unexpected soak stop shape: {args!r}")
    try:
        grace = int(args[1])
    except ValueError:
        return fail(f"unexpected soak stop grace: {args[1]!r}")
    if grace < 0:
        return fail(f"unexpected soak stop grace: {args[1]!r}")
    target = args[2]
    if target not in soak_worker_names():
        return fail(f"stop of non-run container: {target}")
    if os.environ.get("STUB_DOCKER_STOP_FAIL") == "1":
        sys.stderr.write("stub-docker: stop refused\\n")
        return 1
    if os.environ.get("STUB_DOCKER_STOP_FAIL_ONCE") == "1":
        # Fail exactly the first stop (the main-flow retirement);
        # later stops (signal-time recovery) succeed. The marker
        # lives in the shared tmp; stop invocations are sequential,
        # so first-vs-rest is total, never racy.
        once_marker = os.path.join(
            os.environ.get("STUB_CONTAINER_TMP", ""), "stop-fail-once.fired"
        )
        if not os.path.exists(once_marker):
            try:
                with open(once_marker, "w") as handle:
                    handle.write("fired\\n")
            except OSError:
                pass
            sys.stderr.write("stub-docker: stop refused (once)\\n")
            return 1
    if os.environ.get("STUB_DOCKER_STOP_HANG") == "1":
        time.sleep(600)
    tmp = os.environ.get("STUB_CONTAINER_TMP", "")
    # Stop kills the worker tree; the stub tmp (the result
    # filesystem) persists, like a stopped container's fs.
    remove_soak_workers(tmp)
    print(target)
    return 0


def soak_result_payload(path):
    # Content producer for the owned result copy. Returns ("ok",
    # content), ("missing", "") or ("bad", diagnostic); the caller
    # renders its verb's diagnostics.
    if not path.startswith("/tmp/soak_result-") or not path.endswith(
        ".txt"
    ):
        return ("bad", f"unexpected soak result path: {path!r}")
    run_id = path[len("/tmp/soak_result-") : -len(".txt")]
    if not run_id or "/" in run_id:
        return ("bad", f"unexpected soak result path: {path!r}")
    if os.environ.get("STUB_SOAK_RESULT_HANG") == "1":
        time.sleep(600)
    tmp = os.environ.get("STUB_CONTAINER_TMP", "")
    mode = os.environ.get("STUB_SOAK_RESULT_MODE", "")
    if not mode:
        try:
            with open(os.path.join(tmp, os.path.basename(path))) as handle:
                return ("ok", handle.read())
        except OSError:
            return ("missing", "")
    if mode == "missing":
        return ("missing", "")
    if mode == "malformed":
        content = "not-a-result\\n"
    elif mode == "stale-id":
        content = json.dumps(
            {
                "schema": "soak-worker-result/1",
                "run_id": "soak-stale-000",
                "complete": True,
                "offered": 3,
                "counts": {
                    "success": 3,
                    "timeout": 0,
                    "error": 0,
                    "unknown": 0,
                    "unfinished": 0,
                },
                "busy_us": 3000,
                "elapsed_s": 1,
                "clamped_ops": 0,
            }
        ) + "\\n"
    elif mode == "huge":
        # Run-matching record whose counts exceed int64 (bash wraps
        # them to a false PASS without representable-bounds checks).
        big = 2**64
        content = json.dumps(
            {
                "schema": "soak-worker-result/1",
                "run_id": run_id,
                "complete": True,
                "offered": big + 1,
                "counts": {
                    "success": 1,
                    "timeout": 0,
                    "error": big,
                    "unknown": 0,
                    "unfinished": 0,
                },
                "busy_us": 1000,
                "elapsed_s": 1,
                "clamped_ops": 0,
            }
        ) + "\\n"
    elif mode == "hostile-id":
        # Foreign run id carrying an injected key/value record plus
        # control bytes: must neither inject counts nor break JSON.
        # (Doubled escapes: this source is itself a Python literal.)
        content = json.dumps(
            {
                "schema": "soak-worker-result/1",
                "run_id": "x\\nsuccess=7\\noffered=7\\t\\x01tail",
                "complete": True,
                "offered": 2,
                "counts": {
                    "success": 2,
                    "timeout": 0,
                    "error": 0,
                    "unknown": 0,
                    "unfinished": 0,
                },
                "busy_us": 2000,
                "elapsed_s": 1,
                "clamped_ops": 0,
            }
        ) + "\\n"
    elif mode in ("bad-sum", "missing-keys", "negative", "bad-types"):
        base_counts = {
            "success": 2,
            "timeout": 0,
            "error": 0,
            "unknown": 0,
            "unfinished": 0,
        }
        if mode == "bad-sum":
            offered = 99
        else:
            offered = 2
        counts = dict(base_counts)
        if mode == "negative":
            counts["error"] = -1
        if mode == "bad-types":
            counts["success"] = "two"
        record = {
            "schema": "soak-worker-result/1",
            "run_id": run_id,
            "complete": True,
            "offered": offered,
            "counts": counts,
            "busy_us": 2000,
            "elapsed_s": 1,
            "clamped_ops": 0,
        }
        if mode == "missing-keys":
            del record["counts"]
        content = json.dumps(record) + "\\n"
    else:
        return ("bad", f"unknown soak result mode: {mode!r}")
    return ("ok", content)


def do_soak_cp(args):
    # Owned result copy: `docker cp RUN:/tmp/soak_result-<id>.txt
    # <hostdest>` reads the retired worker's frozen result (the
    # container was stopped first, so the population cannot advance
    # mid-read).
    if len(args) != 2 or ":" not in args[0]:
        return fail(f"unexpected soak cp shape: {args!r}")
    target, _, path = args[0].partition(":")
    dest = args[1]
    if target not in soak_worker_names():
        return fail(f"cp from non-run container: {target}")
    status, content = soak_result_payload(path)
    if status == "bad":
        return fail(content)
    if status == "missing":
        sys.stderr.write(
            f"Error: No such container:path: {target}:{path}\\n"
        )
        return 1
    try:
        with open(dest, "w") as handle:
            handle.write(content)
    except OSError:
        return fail(f"cp destination unwritable: {dest}")
    return 0


def do_exec(args, kind):
    extra_env = {}
    positional = []
    saw_tty_off = False
    saw_detach = False
    i = 0
    while i < len(args):
        token = args[i]
        if token == "-T":
            saw_tty_off = True
            i += 1
        elif token == "-d":
            saw_detach = True
            i += 1
        elif token == "-i":
            # Real-CLI fidelity: `docker exec -i` forwards stdin (the
            # soak provisions its worker over a pipe); the stub reads
            # stdin regardless, so the flag only needs accepting.
            i += 1
        elif token == "-e" and i + 1 < len(args):
            name, sep, value = args[i + 1].partition("=")
            if sep:
                extra_env[name] = value
            i += 2
        else:
            positional = args[i:]
            break
    # Real-CLI fidelity: -T exists only on compose exec. Plain docker
    # exec rejects it (125), so the stub must too.
    if saw_tty_off and kind == "docker":
        return fail("docker exec has no -T flag")
    if len(positional) < 2:
        return fail(f"unexpected exec shape: {args!r}")
    target = positional[0]
    command = positional[1:]
    if kind == "docker":
        if saw_detach:
            return fail("unexpected detached docker exec (owned work is joined)")
        if target == "consumer-matrix-daemon" and command[:2] == ["sh", "-c"]:
            return do_daemon_fd_count(command[2])
        if target in soak_worker_names():
            return do_soak_worker_exec(command, extra_env)
        if target != run_container_name():
            return fail(f"exec into non-run container: {target}")
    elif target != "consumer-shell":
        return fail(f"unexpected exec service: {target}")
    if saw_detach:
        # Q10 legacy: the unrepaired soak detaches its worker (unowned,
        # unjoined). The dispatch is recorded; nothing is spawned — the
        # race it creates is structural (worker end DURATION+10 vs the
        # controller read at DURATION), proven by the script bytes, and
        # result reads are served directly below.
        tmp = os.environ.get("STUB_CONTAINER_TMP", "")
        if tmp:
            with open(os.path.join(tmp, "detached-manifest.log"), "a") as handle:
                handle.write(f"{target} {' '.join(command)}\\n")
        return 0
    if command == ["cat", "/tmp/soak_result.txt"]:
        return do_legacy_soak_result()
    if command[:2] == ["sh", "-c"]:
        return run_container_shell(command[2], extra_env)
    if command[:1] == ["sh"] and len(command) == 2:
        tmp = os.environ.get("STUB_CONTAINER_TMP", "")
        script = command[1].replace("/tmp/", tmp + "/", 1) if tmp else command[1]
        return run_shim(["sh", script], extra_env)
    return fail(f"unexpected container command: {command!r}")


def spawn_shim(argv, extra_env):
    # Single-fork *argv* out of the CLI group (container-exec
    # fidelity: the shim survives CLI death as an orphan), staying the
    # CLI's child so the CLI reaps its real exit status, and staying in
    # the run session so the leak oracle still sees strays. Returns the
    # shim PID, or None when the fork itself fails.
    try:
        pid = os.fork()
    except OSError:
        return None
    if pid != 0:
        return pid
    try:
        os.setpgid(0, 0)
        devnull = os.open(os.devnull, os.O_RDWR)
        os.dup2(devnull, 0)
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        if devnull > 2:
            os.close(devnull)
        env = dict(os.environ)
        env.update(extra_env)
        try:
            os.execvpe(argv[0], argv, env)
        except OSError:
            pass
        os._exit(127)
    except Exception:
        os._exit(127)


def run_shim(argv, extra_env):
    # Foreground container-exec fidelity: the CLI blocks until the shim
    # exits and reports its REAL, reaped exit status (docker convention:
    # 128+signal for signal death) — never a file the shim wrote about
    # itself. A CLI killed before the reap records nothing.
    index = extra_env.get(
        "COLD_START_SHIM_INDEX", os.environ.get("COLD_START_SHIM_INDEX", "")
    )
    tmp = os.environ.get("STUB_CONTAINER_TMP", "")
    shim_pid = spawn_shim(argv, extra_env)
    if shim_pid is None:
        return 127
    if tmp and index:
        # Spawn record: container removal stops every spawned shim, so
        # the spawned set (not host enumeration) is the kill list.
        with open(os.path.join(tmp, "exec-manifest.log"), "a") as handle:
            handle.write(f"{index} {shim_pid}\\n")
    _, status = os.waitpid(shim_pid, 0)
    if os.WIFEXITED(status):
        code = os.WEXITSTATUS(status)
    elif os.WIFSIGNALED(status):
        code = 128 + os.WTERMSIG(status)
    else:
        code = 127
    if tmp and index:
        with open(os.path.join(tmp, "shim-exits.log"), "a") as handle:
            handle.write(f"{index} {shim_pid} {code}\\n")
    return code


def run_container_shell(script, extra_env):
    if "spawn_one.sh" in script:
        return run_provision(script, extra_env)
    if "ensure_rsa_key" in script:
        return run_soak_provision(script, extra_env)
    return fail("unexpected sh -c payload")


def run_soak_provision(script, extra_env):
    # Interpreted (never executed: /scripts/common.sh exists only in a
    # real container). Records entry; STUB_SOAK_PROVISION_FAIL/HANG
    # fault the setup step.
    _ = (script, extra_env)
    if os.environ.get("STUB_SOAK_PROVISION_FAIL") == "1":
        sys.stderr.write("stub-docker: provision stream reset by peer\\n")
        return 1
    marker_dir = os.environ.get("STUB_MARKER_DIR", "")
    if marker_dir:
        with open(os.path.join(marker_dir, "provision-entered"), "w"):
            pass
    if os.environ.get("STUB_SOAK_PROVISION_HANG") == "1":
        import time

        time.sleep(600)
    return 0


def run_provision(script, extra_env):
    if os.environ.get("STUB_PROVISION_FAIL") == "1":
        sys.stderr.write("stub-docker: provision stream reset by peer\\n")
        return 1
    marker_dir = os.environ.get("STUB_MARKER_DIR", "")
    if marker_dir:
        with open(os.path.join(marker_dir, "provision-entered"), "w"):
            pass
    if os.environ.get("STUB_PROVISION_HANG") == "1":
        import time

        time.sleep(600)
    tmp = os.environ.get("STUB_CONTAINER_TMP", "")
    if not tmp:
        return fail("STUB_CONTAINER_TMP is not set")
    rewritten = script.replace("/tmp/spawn_one.sh", tmp + "/spawn_one.sh")
    return run_local(["sh", "-c", rewritten], extra_env)


def run_local(argv, extra_env):
    env = dict(os.environ)
    env.update(extra_env)
    completed = subprocess.run(argv, env=env)
    return completed.returncode


sys.exit(main(sys.argv[1:]))
"""


def session_members(sid):
    """PIDs whose session id is *sid* (via /proc, no external tools).

    The repaired script runs each owned job in its own process group
    (job control), so a group scan would miss strays; the session still
    contains exactly the run's processes (each run starts its own
    session and nothing it spawns calls setsid).
    """
    members = []
    want = str(sid)
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat_text = (entry / "stat").read_text()
        except OSError:
            continue
        rparen = stat_text.rfind(")")
        if rparen < 0:
            continue
        fields = stat_text[rparen + 2:].split()
        if len(fields) >= 4 and fields[3] == want:
            members.append(int(entry.name))
    return sorted(members)


def nearest_rank(sorted_values, percent):
    """Nearest-rank quantile over an ascending sequence (None when empty)."""
    if not sorted_values:
        return None
    rank = math.ceil(percent / 100.0 * len(sorted_values))
    rank = min(max(rank, 1), len(sorted_values))
    return sorted_values[rank - 1]


class RunOutcome(NamedTuple):
    returncode: int
    output: str
    timed_out: bool
    survivors: list
    elapsed: float


class PerfHarnessCase(unittest.TestCase):
    """Shared stubbed-execution harness for the perf driver scripts."""

    #: Real host tools linked into the restricted farm PATH. Everything else
    #: the scripts may invoke is stubbed (or deliberately absent).
    FARM_TOOLS = (
        "sh",
        "bash",
        "dirname",
        "mktemp",
        "mkdir",
        "rm",
        "mv",
        "cat",
        "touch",
        "awk",
        # `date` is stubbed, not farmed: the host uutils date goes
        # backward intermittently (see DATE_STUB).
        "seq",
        "sort",
        "chmod",
        # Soak worker needs per-op timeouts and content identities in
        # both worlds (same real tools the containers carry).
        "timeout",
        "cksum",
        "python3",
    )

    maxDiff = None

    def setUp(self):
        super().setUp()
        self.tmpdir = tempfile.TemporaryDirectory(prefix="perf-harness-")
        self.root = Path(self.tmpdir.name)
        self.bin = self.root / "bin"
        self.farm = self.root / "farm"
        self.perf = self.root / "scripts" / "perf"
        self.fake_proc = self.root / "proc"
        self.container_tmp = self.root / "container-tmp"
        self.work_tmp = self.root / "work"
        for path in (
            self.bin,
            self.farm,
            self.perf,
            self.fake_proc,
            self.container_tmp,
            self.work_tmp,
        ):
            path.mkdir(parents=True)
        self._link_farm()
        self._write_stub("sleep", SLEEP_STUB)
        self._write_stub("date", DATE_STUB)
        self._write_stub("docker", DOCKER_STUB)
        self._write_stub("pkcs11-tool", PKCS11_TOOL_STUB)
        self._write_stub("top", TOP_STUB)
        self.daemon_pid = DAEMON_PID
        self._tracked_sessions = []

    def tearDown(self):
        for sid in self._tracked_sessions:
            self._kill_session(sid, signal.SIGKILL)
        self.tmpdir.cleanup()
        super().tearDown()

    def _link_farm(self):
        for tool in self.FARM_TOOLS:
            if tool == "python3":
                target = sys.executable
            else:
                target = shutil.which(tool)
            if not target:
                raise AssertionError(f"host tool {tool!r} is required for perf harness tests")
            (self.farm / tool).symlink_to(target)

    def _write_stub(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)

    def stage_script(self, source):
        """Copy the script under test into the temp tree, proving byte identity."""
        staged = self.perf / source.name
        staged.write_bytes(source.read_bytes())
        staged.chmod(0o755)
        self.assertEqual(
            source.read_bytes(),
            staged.read_bytes(),
            "staged script bytes must equal the committed script bytes",
        )
        return staged

    def base_env(self, extra):
        env = {
            "PATH": f"{self.bin}{os.pathsep}{self.farm}",
            "TMPDIR": str(self.work_tmp),
            "LC_ALL": "C",
            "STUB_CONTAINER_TMP": str(self.container_tmp),
            "STUB_DAEMON_PID": self.daemon_pid,
        }
        env.update(extra)
        return env

    @staticmethod
    def _kill_session(sid, sig):
        # Sessions are not signalable as a unit: walk the members. Up to
        # three passes so a fork racing the sweep is still caught.
        for _ in range(3):
            members = session_members(sid)
            if not members:
                return
            for pid in members:
                try:
                    os.kill(pid, sig)
                except (ProcessLookupError, PermissionError):
                    pass
            time.sleep(0.05)

    @staticmethod
    def _drain_session(sid, timeout=3.0):
        """Poll until the session is empty; return any stragglers."""
        deadline = time.monotonic() + timeout
        members = session_members(sid)
        while members and time.monotonic() < deadline:
            time.sleep(0.05)
            members = session_members(sid)
        return members

    def run_bounded(self, argv, extra_env, bound=RUN_BOUND_SECS):
        """Run *argv* in a fresh session under the external session bound."""
        env = self.base_env(extra_env)
        start = time.monotonic()
        proc = subprocess.Popen(
            [str(arg) for arg in argv],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        self._tracked_sessions.append(proc.pid)
        timed_out = False
        try:
            output, _ = proc.communicate(timeout=bound)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._kill_session(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                output, _ = proc.communicate(timeout=5)
        elapsed = time.monotonic() - start
        # The first drain is the leak evidence: anything still present
        # after it genuinely outlived the run. Fallback SIGKILL protects
        # the host but must never overwrite that evidence.
        first_survivors = self._drain_session(proc.pid)
        if first_survivors:
            self._kill_session(proc.pid, signal.SIGKILL)
            self._drain_session(proc.pid)
        return RunOutcome(proc.returncode, output, timed_out, first_survivors, elapsed)

    def assert_completed(self, outcome, bound):
        self.assertFalse(
            outcome.timed_out,
            f"script exceeded the external {bound}s session bound\n"
            f"--- output ---\n{outcome.output}",
        )

    def assert_no_survivors(self, outcome):
        self.assertEqual(
            [],
            outcome.survivors,
            f"owned descendants survived the run: {outcome.survivors}\n"
            f"--- output ---\n{outcome.output}",
        )

    def work_dir_contents(self):
        return sorted(self.work_tmp.iterdir())

    def write_daemon_status(self, body=None):
        pid_dir = self.fake_proc / self.daemon_pid
        pid_dir.mkdir(exist_ok=True)
        status = pid_dir / "status"
        status.write_text(body if body is not None else "Name:\tdaemon\nVmRSS:\t 123456 kB\n")
        return status

    def write_uptime_file(self, body="1000.00 2000.00\n"):
        # A test-owned monotonic clock: valid /proc/uptime content the
        # run reads through COLD_START_UPTIME_PATH. Deleting it
        # mid-await fails every later clock read deterministically.
        path = self.container_tmp / "fake-uptime"
        path.write_text(body)
        return path

    def wait_for_work_file(self, name, timeout=15):
        """Block until the run's scratch dir contains *name*."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                matches = sorted(self.work_tmp.glob(f"tmp.*/{name}"))
            except OSError:
                matches = []
            if matches:
                return matches[0]
            time.sleep(0.02)
        self.fail(f"scratch file {name} never appeared")

    def results_dir(self):
        return self.perf / "results"

    def read_summary(self, name):
        return json.loads((self.results_dir() / name).read_text())

    def read_csv_rows(self, name):
        with (self.results_dir() / name).open(newline="") as handle:
            return list(csv.reader(handle))

    def read_rm_manifest(self):
        """Names passed to `docker rm -f`, in order (shared across suites)."""
        manifest = self.container_tmp / "rm-manifest.log"
        if not manifest.exists():
            return []
        return manifest.read_text().split()


class ColdStartHarnessTest(PerfHarnessCase):
    """Stubbed regressions for scripts/perf/cold_start_storm.sh (Q09)."""

    def _clear_results(self):
        # Subtests share the results dir and the stub manifests: every
        # run must produce fresh evidence, never inherit a previous
        # run's summary or container/shim records.
        results = self.results_dir()
        if results.is_dir():
            shutil.rmtree(results)
        for manifest in (
            "run-manifest.log",
            "rm-manifest.log",
            "inspect-manifest.log",
            "exec-manifest.log",
            "shim-exits.log",
        ):
            try:
                (self.container_tmp / manifest).unlink()
            except FileNotFoundError:
                pass

    def run_cold_start(self, *args, extra_env=None, bound=RUN_BOUND_SECS):
        self._clear_results()
        script = self.stage_script(COLD_START_SRC)
        env = {
            "COLD_START_PROC_ROOT": str(self.fake_proc),
            "COLD_START_SETUP_TIMEOUT_SECS": "10",
            "COLD_START_STORM_TIMEOUT_SECS": "10",
            "COLD_START_SAMPLER_TIMEOUT_SECS": "5",
            # Suite grace matches the script default (5s): the grace
            # bounds container-side discovery, and a 1s grace trips
            # spuriously on slow-CI stub startup, failing runs that
            # the script then correctly reports as FAIL_CLEANUP.
            # Fail-closed removal is pinned by the
            # STUB_DOCKER_RM_FAIL test instead of a tight grace.
            "COLD_START_CLEANUP_GRACE_SECS": "5",
        }
        if extra_env:
            env.update(extra_env)
        return self.run_bounded([BASH, script, *args], env, bound)

    def wait_for_markers(self, names, timeout=10):
        """Block until every marker file exists; fail loudly on timeout."""
        deadline = time.monotonic() + timeout
        missing = [name for name in names if not (self.container_tmp / name).exists()]
        while missing and time.monotonic() < deadline:
            time.sleep(0.02)
            missing = [name for name in names if not (self.container_tmp / name).exists()]
        self.assertEqual([], missing, f"readiness markers never appeared: {missing}")
        return True

    def live_samples_path(self):
        """The in-flight samples.csv inside the run's scratch dir, if any."""
        try:
            matches = sorted(self.work_tmp.glob("tmp.*/samples.csv"))
        except OSError:
            return None
        return matches[0] if matches else None

    def wait_for_sample_rows(self, predicate, timeout=10, minimum=1):
        """Block until *minimum* live sample rows satisfy *predicate*."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            path = self.live_samples_path()
            if path is not None:
                try:
                    lines = path.read_text().splitlines()
                except OSError:
                    lines = []
                if sum(1 for line in lines[1:] if predicate(line)) >= minimum:
                    return True
            time.sleep(0.02)
        self.fail("live sampler evidence never satisfied the predicate in time")

    def popen_cold_start(self, *args, extra_env=None):
        """Start a staged run without joining it (caller owns the lifetime)."""
        self._clear_results()
        script = self.stage_script(COLD_START_SRC)
        env = {
            "COLD_START_PROC_ROOT": str(self.fake_proc),
            "COLD_START_SETUP_TIMEOUT_SECS": "10",
            "COLD_START_STORM_TIMEOUT_SECS": "10",
            "COLD_START_SAMPLER_TIMEOUT_SECS": "5",
            # Same suite grace as run_cold_start: discovery must
            # tolerate slow-CI stub startup (see above).
            "COLD_START_CLEANUP_GRACE_SECS": "5",
        }
        if extra_env:
            env.update(extra_env)
        proc = subprocess.Popen(
            [BASH, str(script), *args],
            env=self.base_env(env),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        self._tracked_sessions.append(proc.pid)
        return proc

    def read_shim_exits(self):
        """Real shim exit statuses reaped by the stub CLIs.

        Returns {index: (pid, exit_code)}. Only CLIs that lived to
        reap their shim appear: a killed CLI records nothing rather
        than fabricating a code for a shim it never joined.
        """
        manifest = self.container_tmp / "shim-exits.log"
        exits = {}
        if not manifest.exists():
            return exits
        for line in manifest.read_text().splitlines():
            parts = line.split()
            if len(parts) != 3:
                continue
            index, pid, code = parts
            exits[int(index)] = (int(pid), int(code))
        return exits

    def assert_shim_exits(self, expected):
        """Pin the real-exit oracle: {index: exit_code} must match."""
        observed = {
            index: code for index, (_, code) in self.read_shim_exits().items()
        }
        self.assertEqual(expected, observed)

    #: Identity the stub attributes to the shared consumer-shell image.
    STUB_SHELL_IMAGE = "stub-shell-image:latest"
    #: Environment the stub attributes to the shared consumer-shell
    #: container; the run container must forward exactly this set.
    STUB_SHELL_ENV = {
        "PKCS11_PROXY_ENDPOINT": "http://daemon:7512",
        "PKCS11_PROXY_CONNECT_TIMEOUT": "5",
        "RUST_LOG": "pkcs11_proxy_ng_shim=warn",
        "DAEMON_HOST": "daemon",
        "DAEMON_PORT": "7512",
    }

    def read_run_manifest(self):
        """The recorded `docker run`, or None when none was attempted."""
        manifest = self.container_tmp / "run-manifest.log"
        if not manifest.exists():
            return None
        lines = manifest.read_text().splitlines()
        if len(lines) < 2 or not lines[1].startswith("label "):
            return None
        try:
            name, network, image = lines[0].split(" ", 2)
        except ValueError:
            return None
        label_key, _, label_value = lines[1][len("label "):].partition("=")
        env = {}
        for line in lines[2:]:
            key, sep, value = line.partition("=")
            if sep:
                env[key] = value
        return (name, network, image, (label_key, label_value), env)

    def read_exec_manifest(self):
        """Shims the stub CLIs spawned: {index: pid}."""
        manifest = self.container_tmp / "exec-manifest.log"
        spawned = {}
        if not manifest.exists():
            return spawned
        for line in manifest.read_text().splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            spawned[int(parts[0])] = int(parts[1])
        return spawned

    def assert_owned_container_cycle(self):
        """Pin run-container ownership: one owned container, run then removed."""
        run = self.read_run_manifest()
        self.assertIsNotNone(run, "no run container was created")
        name, network, image, label, env = run
        self.assertRegex(name, r"^coldstart-[0-9]+-[0-9]+-[0-9]+$")
        self.assertEqual("container:consumer-matrix-shell", network)
        self.assertEqual(self.STUB_SHELL_IMAGE, image)
        self.assertEqual(("coldstart-run-id", name), label)
        self.assertEqual(self.STUB_SHELL_ENV, env)
        self.assertEqual([name], self.read_rm_manifest())

    def assert_no_container_touched(self):
        """Pin pre-work refusal: no container created, none removed."""
        self.assertIsNone(self.read_run_manifest())
        self.assertEqual([], self.read_rm_manifest())

    def assert_cold_start_pass(self, outcome, bound, expected_n):
        self.assert_completed(outcome, bound)
        self.assertEqual(0, outcome.returncode, outcome.output)
        summary = self.read_summary("cold_start.json")
        self.assertEqual("PASS", summary["verdict"])
        self.assertEqual(expected_n, summary["n"])
        self.assertEqual(expected_n, summary["completed"])
        self.assertEqual(expected_n, summary["ok"])
        self.assertEqual(0, summary["fail"])
        self.assertTrue(summary["sampler_ok"])
        self.assertTrue(summary["cleanup_ok"])
        self.assert_shim_exits({i: 0 for i in range(1, expected_n + 1)})
        self.assertEqual(
            set(range(1, expected_n + 1)), set(self.read_exec_manifest())
        )
        self.assert_owned_container_cycle()
        self.assertEqual(self.read_run_manifest()[0], summary["run_container"])
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())
        return summary

    def test_successful_workload_completes_within_bound(self):
        """Q09 box 1: a finished workload must reach its summary in-bounds."""
        self.write_daemon_status()
        outcome = self.run_cold_start("3")
        summary = self.assert_cold_start_pass(outcome, RUN_BOUND_SECS, 3)
        self.assertEqual("diagnostic-multi-client", summary["workload_contract"])
        self.assertEqual(
            {
                "setup_timeout_s": 10,
                "storm_timeout_s": 10,
                "sampler_timeout_s": 5,
                "cleanup_grace_s": 5,
            },
            summary.get("bounds"),
        )

        rows = self.read_csv_rows("cold_start.csv")
        self.assertEqual(["idx", "wall_us", "exit_code"], rows[0])
        self.assertEqual([1, 2, 3], [int(row[0]) for row in rows[1:]])
        self.assertEqual([0, 0, 0], [int(row[2]) for row in rows[1:]])
        walls = sorted(int(row[1]) for row in rows[1:])
        self.assertEqual(3, len(walls))
        self.assertAlmostEqual(
            nearest_rank(walls, 99) / 1000, summary["p99_wall_ms"], delta=1
        )
        self.assertAlmostEqual(walls[-1] / 1000, summary["max_wall_ms"], delta=1)
        self.assertEqual(123456, summary["peak_rss_kb"])
        self.assertEqual(12.5, summary["peak_cpu_pct"])

    def test_failed_workload_reports_non_success(self):
        """Q09 box 2: failed shims fail the verdict with null quantiles."""
        self.write_daemon_status()
        outcome = self.run_cold_start("3", extra_env={"STUB_PKCS11_MODE": "fail"})
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        summary = self.read_summary("cold_start.json")
        self.assertEqual(
            "FAIL_WORKLOAD", summary["verdict"], json.dumps(summary, indent=1)
        )
        self.assertEqual(3, summary["completed"])
        self.assertEqual(0, summary["ok"])
        self.assertEqual(3, summary["fail"])
        self.assertFalse(summary["workload_timeout"])
        self.assertIsNone(summary["p99_wall_ms"])
        self.assertIsNone(summary["max_wall_ms"])
        self.assertTrue(summary["sampler_ok"])
        self.assertTrue(summary["cleanup_ok"])
        self.assert_shim_exits({1: 1, 2: 1, 3: 1})
        self.assertEqual({1, 2, 3}, set(self.read_exec_manifest()))
        self.assert_owned_container_cycle()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_crashed_shim_is_not_reported_successful(self):
        """Round 4 finding 1: death after a success report still fails."""
        self.write_daemon_status()
        outcome = self.run_cold_start("1", extra_env={"STUB_PKCS11_MODE": "boom"})
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        summary = self.read_summary("cold_start.json")
        self.assertEqual(
            "FAIL_WORKLOAD", summary["verdict"], json.dumps(summary, indent=1)
        )
        self.assertEqual(1, summary["completed"])
        self.assertEqual(0, summary["ok"])
        self.assertEqual(1, summary["fail"])
        rows = self.read_csv_rows("cold_start.csv")
        self.assertEqual(1, int(rows[1][2]))
        self.assert_shim_exits({1: 1})
        self.assertEqual({1}, set(self.read_exec_manifest()))
        self.assert_owned_container_cycle()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_hung_workload_is_bounded_and_reported(self):
        """Q09 box 2: a hung workload is killed at the storm bound, not waited out."""
        self.write_daemon_status()
        outcome = self.run_cold_start(
            "3",
            extra_env={
                "STUB_PKCS11_MODE": "hang",
                "COLD_START_STORM_TIMEOUT_SECS": "2",
            },
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertLess(outcome.elapsed, 15, outcome.output)
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        summary = self.read_summary("cold_start.json")
        self.assertEqual(
            "FAIL_WORKLOAD", summary["verdict"], json.dumps(summary, indent=1)
        )
        self.assertTrue(summary["workload_timeout"])
        self.assertEqual(0, summary["completed"])
        self.assertEqual(0, summary["ok"])
        self.assertEqual(0, summary["fail"])
        self.assertIsNone(summary["p99_wall_ms"])
        self.assertTrue(summary["sampler_ok"])
        self.assertTrue(summary["cleanup_ok"])
        # Killed CLIs record nothing: no fabricated codes for shims
        # they never joined — but every shim was spawned, then removed
        # with the run container.
        self.assert_shim_exits({})
        self.assertEqual({1, 2, 3}, set(self.read_exec_manifest()))
        self.assert_owned_container_cycle()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_sampler_without_measurements_reports_failure(self):
        """Q09 box 2: a blind sampler fails the verdict; peaks stay null."""
        cases = {
            "no-cpu": ("Name:\tdaemon\nVmRSS:\t 123456 kB\n", "1"),
            "no-rss": ("Name:\tdaemon\n", None),
            "neither": ("Name:\tdaemon\n", "1"),
        }
        for name, (status_body, top_fail) in cases.items():
            with self.subTest(case=name):
                self.write_daemon_status(status_body)
                extra = {}
                if top_fail is not None:
                    extra["STUB_TOP_FAIL"] = top_fail
                outcome = self.run_cold_start("2", extra_env=extra)
                self.assert_completed(outcome, RUN_BOUND_SECS)
                self.assertNotEqual(0, outcome.returncode, outcome.output)
                summary = self.read_summary("cold_start.json")
                self.assertEqual(
                    "FAIL_SAMPLER", summary["verdict"], json.dumps(summary, indent=1)
                )
                # The workload itself passed; only the sampler failed.
                self.assertEqual(2, summary["ok"])
                self.assertEqual(0, summary["fail"])
                self.assertFalse(summary["sampler_ok"])
                self.assertTrue(summary["cleanup_ok"])
                if top_fail is not None:
                    self.assertIsNone(summary["peak_cpu_pct"])
                else:
                    self.assertEqual(12.5, summary["peak_cpu_pct"])
                if "VmRSS" in status_body:
                    self.assertEqual(123456, summary["peak_rss_kb"])
                else:
                    self.assertIsNone(summary["peak_rss_kb"])
                self.assert_owned_container_cycle()
                self.assert_no_survivors(outcome)
                self.assertEqual([], self.work_dir_contents())

    def test_hung_sampler_is_bounded_and_reported(self):
        """Q09 box 2: a sampler that never wakes is killed at its own bound."""
        self.write_daemon_status()
        outcome = self.run_cold_start(
            "2",
            extra_env={
                "COLD_START_SAMPLE_INTERVAL": "7",
                "COLD_START_SAMPLER_TIMEOUT_SECS": "2",
                "STUB_SLEEP_HANG_ON": "7",
            },
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertLess(outcome.elapsed, 15, outcome.output)
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        summary = self.read_summary("cold_start.json")
        self.assertEqual(
            "FAIL_SAMPLER", summary["verdict"], json.dumps(summary, indent=1)
        )
        self.assertEqual(2, summary["ok"])
        self.assertTrue(summary["sampler_killed"])
        self.assertNotEqual(0, summary["sampler_exit"])
        self.assertFalse(summary["sampler_ok"])
        self.assertTrue(summary["cleanup_ok"])
        self.assert_owned_container_cycle()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_missing_process_refuses_run(self):
        """Q09 box 2: an unmeasurable daemon refuses the run, not zero rows."""
        # No status file at all: the daemon PID cannot be measured.
        outcome = self.run_cold_start("3", bound=REJECT_BOUND_SECS)
        self.assert_completed(outcome, REJECT_BOUND_SECS)
        self.assertEqual(2, outcome.returncode, outcome.output)
        self.assertIn("not measurable", outcome.output)
        self.assertFalse((self.results_dir() / "cold_start.json").exists())
        self.assert_no_container_touched()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_daemon_death_mid_run_fails_workload(self):
        """Q09 box 2: a daemon lost mid-storm fails the workload verdict.

        Ordering is structural, not timed: the deleter waits for workload
        entry (all shims announced) plus two landed samples before
        deleting; the stub shims wait for the deletion and then for the
        test's release, which is written only after a post-deletion
        sampler row has landed. Pre- and post-deletion evidence both
        exist regardless of scheduling.
        """
        status_path = self.write_daemon_status()
        release_path = self.container_tmp / "release"
        proc = self.popen_cold_start(
            "3",
            extra_env={
                "STUB_PKCS11_MODE": "fail-when-daemon-gone",
                "STUB_DAEMON_STATUS_PATH": str(status_path),
                "STUB_RELEASE_PATH": str(release_path),
                "STUB_MARKER_DIR": str(self.container_tmp),
            },
        )
        try:
            # Order the kill after workload entry plus two landed samples.
            self.wait_for_markers(["entered-1", "entered-2", "entered-3"], timeout=10)
            self.wait_for_sample_rows(lambda line: True, timeout=10, minimum=2)
            status_path.unlink()
            # Hold the failing shims until post-deletion sampler evidence
            # has landed, then release them to finish the run.
            self.wait_for_sample_rows(
                lambda line: len(line.split(",")) > 1 and line.split(",")[1] == "",
                timeout=10,
            )
            release_path.touch()
            try:
                output, _ = proc.communicate(timeout=RUN_BOUND_SECS)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail(f"run exceeded the external {RUN_BOUND_SECS}s bound")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"run leaked descendants: {survivors}")
        self.assertNotEqual(0, proc.returncode, output)
        summary = self.read_summary("cold_start.json")
        self.assertEqual(
            "FAIL_WORKLOAD", summary["verdict"], json.dumps(summary, indent=1)
        )
        self.assertEqual(3, summary["completed"])
        self.assertEqual(0, summary["ok"])
        self.assertEqual(3, summary["fail"])
        self.assertFalse(summary["workload_timeout"])
        # Partial sampler evidence is preserved, not zero-filled.
        sample_rows = self.read_csv_rows("cold_start_daemon_samples.csv")
        rss_values = [row[1] for row in sample_rows[1:]]
        self.assertIn("123456", rss_values)
        self.assertIn("", rss_values)
        self.assert_owned_container_cycle()
        self.assertEqual([], self.work_dir_contents())

    def _interrupt_test(self, sig, expected_code, extra_env=None):
        self.write_daemon_status()
        env = {
            "COLD_START_STORM_TIMEOUT_SECS": "30",
            "STUB_PKCS11_MODE": "hang",
            "STUB_MARKER_DIR": str(self.container_tmp),
        }
        if extra_env:
            env.update(extra_env)
        proc = self.popen_cold_start("3", extra_env=env)
        try:
            # Prove the intended state (all workers entered, sampler
            # sampling) before interrupting; no fixed delays.
            self.wait_for_markers(["entered-1", "entered-2", "entered-3"], timeout=10)
            self.wait_for_sample_rows(lambda line: True, timeout=10, minimum=1)
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            os.kill(proc.pid, sig)
            try:
                output, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                script_dead = proc.poll() is not None
                stranded = session_members(proc.pid)
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                if script_dead:
                    self.fail(
                        f"script died on {signal.Signals(sig).name} but "
                        f"stranded descendants held the run open: {stranded}"
                    )
                self.fail(f"script ignored {signal.Signals(sig).name}")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"interrupt leaked descendants: {survivors}")
        self.assertEqual([], self.work_dir_contents())
        self.assertEqual(expected_code, proc.returncode, output)
        # The interrupt produces a terminal failure record, not silence.
        summary_path = self.results_dir() / "cold_start.json"
        self.assertTrue(summary_path.exists(), "interrupt wrote no terminal summary")
        summary = json.loads(summary_path.read_text())
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        self.assertEqual(signal.Signals(sig).name, summary["signal"])
        self.assertEqual(3, summary["n"])
        self.assertTrue(summary["cleanup_ok"])
        self.assertEqual([], summary["unresolved_pids"])
        self.assertIsNone(summary["completed"])
        self.assertIsNone(summary["p99_wall_ms"])
        self.assertIsNone(summary["peak_rss_kb"])
        self.assert_owned_container_cycle()
        self.assertEqual(self.read_run_manifest()[0], summary["run_container"])

    def test_interrupt_sigterm_cleans_up(self):
        """Q09 box 2: SIGTERM stops owned children and removes scratch state."""
        self._interrupt_test(signal.SIGTERM, 143)

    def test_interrupt_sigint_cleans_up(self):
        """Q09 box 2: SIGINT stops owned children and removes scratch state."""
        self._interrupt_test(signal.SIGINT, 130)

    def test_interrupt_with_octal_grace_cleans_up(self):
        """Round 2 finding 5: cleanup arithmetic has no octal hole."""
        self._interrupt_test(
            signal.SIGTERM, 143, extra_env={"COLD_START_CLEANUP_GRACE_SECS": "08"}
        )

    def test_n_equals_1_supported_contract(self):
        """Q09 box 2: N=1 is the supported single-client run; rank-1 edge pinned."""
        self.write_daemon_status()
        outcome = self.run_cold_start("1")
        summary = self.assert_cold_start_pass(outcome, RUN_BOUND_SECS, 1)
        self.assertEqual("supported-single-client", summary["workload_contract"])
        rows = self.read_csv_rows("cold_start.csv")
        self.assertEqual(2, len(rows))
        wall_ms = int(rows[1][1]) / 1000
        self.assertAlmostEqual(wall_ms, summary["p99_wall_ms"], delta=1)
        self.assertAlmostEqual(wall_ms, summary["max_wall_ms"], delta=1)

    def test_n100_nearest_rank_convention(self):
        """Q09 box 2: p99 is nearest-rank over the successful population."""
        self.write_daemon_status()
        # This test pins the quantile convention, not storm speed: 100
        # parallel stub workers need a generous storm bound on a
        # loaded box (a 10s storm bound trips spuriously and the
        # script then correctly reports FAIL_WORKLOAD). Storm-speed
        # bounds are pinned by the hung-workload tests instead.
        outcome = self.run_cold_start(
            "100",
            extra_env={"COLD_START_STORM_TIMEOUT_SECS": "120"},
            bound=150,
        )
        summary = self.assert_cold_start_pass(outcome, 150, 100)
        rows = self.read_csv_rows("cold_start.csv")
        self.assertEqual(101, len(rows))
        walls = sorted(int(row[1]) for row in rows[1:])
        # Nearest-rank p99 over n=100: rank ceil(99/100*100)=99 -> index 98.
        self.assertAlmostEqual(walls[98] / 1000, summary["p99_wall_ms"], delta=1)
        self.assertAlmostEqual(walls[99] / 1000, summary["max_wall_ms"], delta=1)

    def test_mixed_population_quantiles_use_successful_rows(self):
        """Q09 box 2: quantiles cover successful rows only, never failures."""
        self.write_daemon_status()
        outcome = self.run_cold_start(
            "3",
            extra_env={
                "STUB_PKCS11_MODE": "fail-index",
                "STUB_PKCS11_FAIL_INDEX": "2",
                # Deterministic injected durations: the stub clock
                # returns exact per-worker walls, so the failing wall is
                # the global maximum by injection — no scheduling margin
                # is assumed anywhere.
                "STUB_DATE_MODE": "fixed",
                "STUB_DATE_FIXED_WALLS": "1:2000000,3:3000000,2:9000000",
            },
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        summary = self.read_summary("cold_start.json")
        self.assertEqual(
            "FAIL_WORKLOAD", summary["verdict"], json.dumps(summary, indent=1)
        )
        self.assertEqual(3, summary["completed"])
        self.assertEqual(2, summary["ok"])
        self.assertEqual(1, summary["fail"])
        rows = self.read_csv_rows("cold_start.csv")
        by_idx = {int(row[0]): (int(row[1]), int(row[2])) for row in rows[1:]}
        self.assertEqual(1, by_idx[2][1])
        self.assertEqual(0, by_idx[1][1])
        self.assertEqual(0, by_idx[3][1])
        # Exact injected walls: any scheduling dependence would move these.
        self.assertEqual(2000000, by_idx[1][0])
        self.assertEqual(3000000, by_idx[3][0])
        self.assertEqual(9000000, by_idx[2][0])
        successful = sorted([by_idx[1][0], by_idx[3][0]])
        self.assertAlmostEqual(
            nearest_rank(successful, 99) / 1000, summary["p99_wall_ms"], delta=1
        )
        self.assertAlmostEqual(successful[-1] / 1000, summary["max_wall_ms"], delta=1)
        # Distinction pin: the reported quantiles cannot come from the
        # all-rows population, whose maximum is the failing shim's wall.
        self.assertLess(
            summary["p99_wall_ms"] * 1000, by_idx[2][0] - 100000
        )
        self.assert_shim_exits({1: 0, 2: 1, 3: 0})
        self.assertEqual({1, 2, 3}, set(self.read_exec_manifest()))
        self.assert_owned_container_cycle()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_stepped_clock_rows_rejected_as_malformed(self):
        """Q09 boxes 2-3: negative walls are refused, never averaged in."""
        self.write_daemon_status()
        outcome = self.run_cold_start(
            "3", extra_env={"STUB_DATE_MODE": "backward"}
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        summary = self.read_summary("cold_start.json")
        self.assertEqual(
            "FAIL_WORKLOAD", summary["verdict"], json.dumps(summary, indent=1)
        )
        self.assertEqual(0, summary["completed"])
        self.assertEqual(3, summary["malformed_rows"])
        self.assertEqual(0, summary["ok"])
        self.assertEqual(0, summary["fail"])
        self.assertFalse(summary["workload_timeout"])
        self.assertIn("malformed workload rows: 3", summary["reasons"])
        self.assertIsNone(summary["p99_wall_ms"])
        self.assertIsNone(summary["max_wall_ms"])
        self.assertLess(summary["storm_elapsed_ms"], 0)
        self.assertTrue(summary["sampler_ok"])
        self.assertTrue(summary["cleanup_ok"])
        self.assert_owned_container_cycle()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_term_ignoring_shim_removed_with_container(self):
        """Round 4 findings 2-3: removal stops shims no signal can reach."""
        self.write_daemon_status()
        outcome = self.run_cold_start(
            "2",
            extra_env={
                "STUB_PKCS11_MODE": "ignore-term-hang",
                "COLD_START_STORM_TIMEOUT_SECS": "2",
            },
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertLess(outcome.elapsed, 15, outcome.output)
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        summary = self.read_summary("cold_start.json")
        self.assertEqual(
            "FAIL_WORKLOAD", summary["verdict"], json.dumps(summary, indent=1)
        )
        self.assertTrue(summary["workload_timeout"])
        self.assertTrue(summary["cleanup_ok"])
        # Both shims were spawned, neither CLI reaped one, and the
        # owned container (with both shims) was removed.
        self.assertEqual({1, 2}, set(self.read_exec_manifest()))
        self.assert_shim_exits({})
        self.assert_owned_container_cycle()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_backward_clock_hung_workload_still_bounded(self):
        """Round 2 finding 4: bounds are monotonic, not realtime."""
        self.write_daemon_status()
        outcome = self.run_cold_start(
            "2",
            extra_env={
                "STUB_PKCS11_MODE": "hang",
                "STUB_DATE_MODE": "backward",
                "COLD_START_STORM_TIMEOUT_SECS": "2",
            },
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertLess(outcome.elapsed, 15, outcome.output)
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        summary = self.read_summary("cold_start.json")
        self.assertEqual(
            "FAIL_WORKLOAD", summary["verdict"], json.dumps(summary, indent=1)
        )
        self.assertTrue(summary["workload_timeout"])
        self.assert_owned_container_cycle()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_canonical_integers_accepted(self):
        """Round 2 finding 5: non-canonical decimals work (no octal holes)."""
        self.write_daemon_status()
        outcome = self.run_cold_start(
            "01",
            extra_env={
                "COLD_START_STORM_TIMEOUT_SECS": "08",
                "COLD_START_SAMPLER_TIMEOUT_SECS": "010",
                "COLD_START_CLEANUP_GRACE_SECS": "007",
            },
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertEqual(0, outcome.returncode, outcome.output)
        try:
            summary = self.read_summary("cold_start.json")
        except json.JSONDecodeError as exc:
            self.fail(f"summary is not valid JSON: {exc}")
        self.assertEqual("PASS", summary["verdict"])
        self.assertEqual(1, summary["n"])
        self.assertEqual("supported-single-client", summary["workload_contract"])
        self.assertEqual(
            {
                "setup_timeout_s": 10,
                "storm_timeout_s": 8,
                "sampler_timeout_s": 10,
                "cleanup_grace_s": 7,
            },
            summary.get("bounds"),
        )
        self.assert_owned_container_cycle()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_oversized_inputs_rejected(self):
        """Round 2 finding 5: unrepresentable/out-of-range inputs exit 2."""
        self.write_daemon_status()
        real_seq = shutil.which("seq")
        self.assertIsNotNone(real_seq)
        seq_calls = self.container_tmp / "seq-calls.log"
        (self.bin / "seq").write_text(
            "#!/usr/bin/env python3\n"
            "import os, sys\n"
            f"real_seq = {real_seq!r}\n"
            f"calls = {str(seq_calls)!r}\n"
            "with open(calls, 'a') as handle:\n"
            "    handle.write(' '.join(sys.argv[1:]) + '\\n')\n"
            "try:\n"
            "    last = int(sys.argv[-1])\n"
            "except ValueError:\n"
            "    last = 0\n"
            "# Guard the shared host: never actually enumerate a storm the\n"
            "# repaired script would refuse up front.\n"
            "if last > 100000:\n"
            "    sys.exit(2)\n"
            "os.execv(real_seq, [real_seq, *sys.argv[1:]])\n"
        )
        (self.bin / "seq").chmod(0o755)
        cases = {
            "n-bignum": ("99999999999999999999", {}),
            "n-over-cap": ("100001", {}),
            "storm-over-cap": ("2", {"COLD_START_STORM_TIMEOUT_SECS": "31536001"}),
            "sampler-over-cap": ("2", {"COLD_START_SAMPLER_TIMEOUT_SECS": "99999999999"}),
            "grace-over-cap": ("2", {"COLD_START_CLEANUP_GRACE_SECS": "99999999999"}),
            "startup-over-cap": ("2", {"COLD_START_STARTUP_SLEEP": "3601"}),
            "interval-over-cap": ("2", {"COLD_START_SAMPLE_INTERVAL": "3601"}),
        }
        for name, (count, extra) in cases.items():
            with self.subTest(case=name):
                outcome = self.run_cold_start(count, extra_env=extra, bound=REJECT_BOUND_SECS)
                calls = seq_calls.read_text() if seq_calls.exists() else ""
                self.assert_completed(outcome, REJECT_BOUND_SECS)
                self.assertEqual(
                    2,
                    outcome.returncode,
                    f"seq calls: {calls!r}\n{outcome.output}",
                )
                self.assertFalse((self.results_dir() / "cold_start.json").exists())
                self.assert_no_container_touched()
                self.assert_no_survivors(outcome)
                self.assertEqual([], self.work_dir_contents())
        # The repaired script rejects before spawning: seq never ran.
        calls = seq_calls.read_text() if seq_calls.exists() else ""
        self.assertFalse(seq_calls.exists(), f"seq ran during rejection: {calls!r}")

    def test_comma_cpu_measurement_rejected(self):
        """Round 2 finding 6: locale-shaped CPU text is not a measurement."""
        self.write_daemon_status()
        outcome = self.run_cold_start("2", extra_env={"STUB_TOP_CPU": "12,5"})
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        summary = self.read_summary("cold_start.json")
        self.assertEqual(
            "FAIL_SAMPLER", summary["verdict"], json.dumps(summary, indent=1)
        )
        self.assertEqual(2, summary["ok"])
        self.assertIsNone(summary["peak_cpu_pct"])
        self.assertEqual(123456, summary["peak_rss_kb"])
        sample_rows = self.read_csv_rows("cold_start_daemon_samples.csv")
        for row in sample_rows[1:]:
            self.assertNotIn("12,5", ",".join(row))
        self.assert_owned_container_cycle()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_leading_zero_measurements_rejected(self):
        """Round 2 finding 6: non-canonical numerics stay out of the JSON."""
        self.write_daemon_status("Name:\tdaemon\nVmRSS:\t 007 kB\n")
        outcome = self.run_cold_start("2")
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        try:
            summary = self.read_summary("cold_start.json")
        except json.JSONDecodeError as exc:
            self.fail(f"summary is not valid JSON: {exc}")
        self.assertEqual(
            "FAIL_SAMPLER", summary["verdict"], json.dumps(summary, indent=1)
        )
        self.assertIsNone(summary["peak_rss_kb"])
        self.assertEqual(2, summary["ok"])
        self.assert_owned_container_cycle()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_tampered_samples_fail_closed(self):
        """Round 2 finding 6: malformed sampler rows fail the verdict."""
        self.write_daemon_status()
        release = self.container_tmp / "tamper-release"
        proc = self.popen_cold_start(
            "2",
            extra_env={
                "STUB_PKCS11_MODE": "wait-release",
                "STUB_MARKER_DIR": str(self.container_tmp),
                "STUB_RELEASE_PATH": str(release),
            },
        )
        try:
            self.wait_for_markers(["entered-1", "entered-2"], timeout=10)
            self.wait_for_sample_rows(lambda line: True, timeout=10, minimum=1)
            path = self.live_samples_path()
            self.assertIsNotNone(path, "sampler evidence never appeared")
            with path.open("a") as handle:
                handle.write("GARBAGE,LINE\n")
            # The release gate holds the workload: the tamper provably
            # lands in the live evidence before the run can finish it.
            self.assertIn(
                "GARBAGE,LINE",
                path.read_text().splitlines(),
                "tamper did not land in the live evidence",
            )
            release.touch()
            try:
                output, _ = proc.communicate(timeout=RUN_BOUND_SECS)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail(f"run exceeded the external {RUN_BOUND_SECS}s bound")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        sample_rows = self.read_csv_rows("cold_start_daemon_samples.csv")
        self.assertIn(["GARBAGE", "LINE"], sample_rows, "tamper missed the run window")
        self.assertNotEqual(0, proc.returncode, output)
        summary = self.read_summary("cold_start.json")
        self.assertEqual(
            "FAIL_SAMPLER", summary["verdict"], json.dumps(summary, indent=1)
        )
        self.assertGreaterEqual(summary["malformed_samples"], 1)
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"run leaked descendants: {survivors}")
        self.assert_owned_container_cycle()
        self.assertEqual([], self.work_dir_contents())

    def test_unknown_process_state_fails_closed(self):
        """Round 2 finding 2: unreadable state is unknown, never gone."""
        self.write_daemon_status()
        outcome = self.run_cold_start("2", extra_env={"COLD_START_STAT_READER": "false"})
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        summary = self.read_summary("cold_start.json")
        self.assertEqual(
            "FAIL_CLEANUP", summary["verdict"], json.dumps(summary, indent=1)
        )
        self.assertFalse(summary["cleanup_ok"])
        self.assertGreater(len(summary["unresolved_pids"]), 0)
        # The children were really stopped despite the blind verification.
        self.assert_owned_container_cycle()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_blind_reader_with_hung_sampler_kills_descendants(self):
        """Round 3 finding 1: blind escalation stops unenumerated descendants."""
        self.write_daemon_status()
        outcome = self.run_cold_start(
            "2",
            extra_env={
                "COLD_START_STAT_READER": "false",
                "COLD_START_SAMPLE_INTERVAL": "7",
                "COLD_START_SAMPLER_TIMEOUT_SECS": "2",
                "STUB_SLEEP_HANG_ON": "7",
            },
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertLess(outcome.elapsed, 15, outcome.output)
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        summary = self.read_summary("cold_start.json")
        self.assertEqual(
            "FAIL_CLEANUP", summary["verdict"], json.dumps(summary, indent=1)
        )
        self.assertFalse(summary["cleanup_ok"])
        self.assertGreater(len(summary["unresolved_pids"]), 0)
        # The sampler's hung sleep grandchild cannot be enumerated while
        # blind, but per-job group ownership still stops it.
        self.assert_owned_container_cycle()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_storm_start_clock_failure_exits_setup_error(self):
        """Round 3 finding 3: pre-work clock failure exits 2 with cleanup."""
        self.write_daemon_status()
        outcome = self.run_cold_start(
            "2", extra_env={"STUB_DATE_FAIL_CALLER": "storm-start"}
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertEqual(2, outcome.returncode, outcome.output)
        self.assertFalse(
            (self.results_dir() / "cold_start.json").exists(), outcome.output
        )
        # Pre-work refusal, but the run container already existed: the
        # exit trap removed it.
        self.assert_owned_container_cycle()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_storm_end_clock_failure_writes_terminal_record(self):
        """Round 3 finding 3: post-start clock failure is a FAIL verdict."""
        self.write_daemon_status()
        outcome = self.run_cold_start(
            "2", extra_env={"STUB_DATE_FAIL_CALLER": "storm-end"}
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        self.assertTrue(
            (self.results_dir() / "cold_start.json").exists(), outcome.output
        )
        summary = self.read_summary("cold_start.json")
        self.assertEqual(
            "FAIL_WORKLOAD", summary["verdict"], json.dumps(summary, indent=1)
        )
        self.assertIsNone(summary["storm_elapsed_ms"])
        self.assertIn(
            "storm elapsed time could not be measured: "
            "realtime clock read failed",
            summary["reasons"],
        )
        # The rows themselves are fine; only the aggregate elapsed is lost.
        self.assertEqual(2, summary["completed"])
        self.assertEqual(2, summary["ok"])
        self.assertTrue(summary["sampler_ok"])
        self.assertTrue(summary["cleanup_ok"])
        self.assert_owned_container_cycle()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_run_removal_failure_fails_cleanup(self):
        """Round 4 findings 2-3: an unremovable run container fails closed."""
        self.write_daemon_status()
        outcome = self.run_cold_start(
            "2", extra_env={"STUB_DOCKER_RM_FAIL": "1"}
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        summary = self.read_summary("cold_start.json")
        self.assertEqual(
            "FAIL_CLEANUP", summary["verdict"], json.dumps(summary, indent=1)
        )
        self.assertFalse(summary["cleanup_ok"])
        # The work itself completed; only container removal failed. The
        # removal was attempted against exactly the owned container.
        self.assertEqual(2, summary["completed"])
        self.assertEqual(2, summary["ok"])
        self.assertTrue(summary["sampler_ok"])
        self.assertIn(
            "container-side termination could not be verified",
            summary["reasons"],
        )
        run = self.read_run_manifest()
        self.assertIsNotNone(run)
        # One bounded attempt: a refused removal is operator-actionable
        # via run_container, not silently retried.
        self.assertEqual([run[0]], self.read_rm_manifest())
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def wait_for_manifest_lines(self, name, count, timeout=10):
        """Block until the stub manifest holds >= count lines."""
        path = self.container_tmp / name
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                lines = path.read_text().splitlines()
            except OSError:
                lines = []
            if len(lines) >= count:
                return lines
            time.sleep(0.02)
        self.fail(f"{name} never reached {count} lines")

    def test_run_container_creation_timeout_reconciles(self):
        """Round 5 finding 1: ambiguous creation reconciles by identity."""
        self.write_daemon_status()
        cases = {
            # (extra env, removal expectation: "removed" = the owned
            # container was verified and removed; "refused" = no removal
            # was attempted and stderr names the leftover).
            "reconciled": ({}, "removed"),
            "label-mismatch": ({"STUB_RUN_LABEL_MISMATCH": "1"}, "refused"),
            "inspect-error-daemon": (
                {
                    "STUB_RECONCILE_INSPECT_FAIL": (
                        "Cannot connect to the Docker daemon at "
                        "unix:///var/run/docker.sock. Is the docker "
                        "daemon running?"
                    )
                },
                "refused",
            ),
            # Round 6 finding 1: a transport error mentioning "no such
            # host" must not read as container absence.
            "inspect-error-no-such-host": (
                {
                    "STUB_RECONCILE_INSPECT_FAIL": (
                        "lookup daemon on 127.0.0.11:53: no such host"
                    )
                },
                "refused",
            ),
            "inspect-hang": ({"STUB_RECONCILE_INSPECT_HANG": "1"}, "refused"),
        }
        for name, (extra, expectation) in cases.items():
            with self.subTest(case=name):
                extra = dict(extra)
                extra["STUB_DOCKER_RUN_HANG"] = "1"
                extra["COLD_START_SETUP_TIMEOUT_SECS"] = "2"
                extra["COLD_START_CLEANUP_GRACE_SECS"] = "2"
                outcome = self.run_cold_start(
                    "2", extra_env=extra, bound=RUN_BOUND_SECS
                )
                self.assert_completed(outcome, RUN_BOUND_SECS)
                self.assertEqual(2, outcome.returncode, outcome.output)
                self.assertIn("timed out", outcome.output)
                self.assertFalse((self.results_dir() / "cold_start.json").exists())
                run = self.read_run_manifest()
                self.assertIsNotNone(run, "stub never recorded the creation")
                if expectation == "removed":
                    self.assertEqual([run[0]], self.read_rm_manifest())
                else:
                    self.assertEqual([], self.read_rm_manifest())
                    self.assertIn("leaving it in place", outcome.output)
                self.assert_no_survivors(outcome)
                self.assertEqual([], self.work_dir_contents())

    def test_run_container_creation_interrupt_reconciles(self):
        """Round 5 finding 1: a signal during creation still reconciles."""
        self.write_daemon_status()
        proc = self.popen_cold_start(
            "2",
            extra_env={
                "STUB_DOCKER_RUN_HANG": "1",
                "COLD_START_SETUP_TIMEOUT_SECS": "30",
            },
        )
        try:
            # Barrier: the creation committed (manifested) but was never
            # acknowledged (the CLI hangs), so the signal lands in the
            # ambiguous window deterministically.
            self.wait_for_manifest_lines("run-manifest.log", 1, timeout=10)
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            os.kill(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("script ignored SIGTERM during run-container creation")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"interrupt leaked descendants: {survivors}")
        self.assertEqual(143, proc.returncode, output)
        summary_path = self.results_dir() / "cold_start.json"
        self.assertTrue(summary_path.exists(), "interrupt wrote no terminal summary")
        summary = json.loads(summary_path.read_text())
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        self.assertEqual("SIGTERM", summary["signal"])
        self.assertIn(
            "interrupted by SIGTERM during setup:run-container",
            summary["reasons"],
        )
        self.assertTrue(summary["cleanup_ok"])
        run = self.read_run_manifest()
        self.assertIsNotNone(run)
        self.assertEqual([run[0]], self.read_rm_manifest())
        self.assertEqual(run[0], summary["run_container"])
        self.assertEqual([], self.work_dir_contents())

    def test_run_container_creation_interrupt_transport_unknown(self):
        """Round 6 finding 1: transport errors are unknown, not absence."""
        self.write_daemon_status()
        proc = self.popen_cold_start(
            "2",
            extra_env={
                "STUB_DOCKER_RUN_HANG": "1",
                "STUB_RECONCILE_INSPECT_FAIL": (
                    "lookup daemon on 127.0.0.11:53: no such host"
                ),
                "COLD_START_SETUP_TIMEOUT_SECS": "30",
            },
        )
        try:
            # Barrier: the creation committed but was never acknowledged,
            # so the trap reconciles against a failing transport.
            self.wait_for_manifest_lines("run-manifest.log", 1, timeout=10)
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            os.kill(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("script ignored SIGTERM during run-container creation")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"interrupt leaked descendants: {survivors}")
        self.assertEqual(143, proc.returncode, output)
        summary_path = self.results_dir() / "cold_start.json"
        self.assertTrue(summary_path.exists(), "interrupt wrote no terminal summary")
        summary = json.loads(summary_path.read_text())
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        self.assertEqual("SIGTERM", summary["signal"])
        self.assertFalse(summary["cleanup_ok"])
        self.assertIn(
            "container-side termination could not be verified",
            summary["reasons"],
        )
        self.assertIn("leaving it in place", output)
        run = self.read_run_manifest()
        self.assertIsNotNone(run)
        self.assertEqual([], self.read_rm_manifest())
        self.assertEqual(run[0], summary["run_container"])
        self.assertEqual([], self.work_dir_contents())

    def test_run_removal_hang_times_out(self):
        """Round 5 finding 2: a stalled removal fails closed under a bound."""
        self.write_daemon_status()
        outcome = self.run_cold_start(
            "2",
            extra_env={
                "STUB_DOCKER_RM_HANG": "always",
                "COLD_START_CLEANUP_GRACE_SECS": "2",
            },
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertLess(outcome.elapsed, 15, outcome.output)
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        summary = self.read_summary("cold_start.json")
        self.assertEqual(
            "FAIL_CLEANUP", summary["verdict"], json.dumps(summary, indent=1)
        )
        self.assertFalse(summary["cleanup_ok"])
        self.assertEqual(2, summary["completed"])
        self.assertEqual(2, summary["ok"])
        self.assertTrue(summary["sampler_ok"])
        self.assertIn(
            "container-side termination could not be verified",
            summary["reasons"],
        )
        # One bounded attempt: the stalled removal times out once and
        # fails closed.
        run = self.read_run_manifest()
        self.assertIsNotNone(run)
        self.assertEqual([run[0]], self.read_rm_manifest())
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_run_removal_clock_failure_settles_helper(self):
        """Round 6 finding 2: a clock failure mid-removal settles the helper."""
        self.write_daemon_status()
        uptime = self.write_uptime_file()
        proc = self.popen_cold_start(
            "2",
            extra_env={
                "STUB_DOCKER_RM_HANG": "always",
                "COLD_START_UPTIME_PATH": str(uptime),
                "COLD_START_CLEANUP_GRACE_SECS": "30",
            },
        )
        try:
            # Barrier: the removal dispatched and stalled, so deleting
            # the test-owned clock lands mid-await deterministically.
            self.wait_for_manifest_lines("rm-manifest.log", 1, timeout=10)
            self.assertIsNone(
                proc.poll(), "script exited before the clock was failed"
            )
            uptime.unlink()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("script stalled after the clock failed mid-removal")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        # The script exits on its own; a discarded helper would survive
        # as a pipe-holding orphan, so drain the session (collecting the
        # leak evidence), SIGKILL any stragglers to release the pipes,
        # then collect the script's own output.
        survivors = self._drain_session(proc.pid)
        if survivors:
            self._kill_session(proc.pid, signal.SIGKILL)
            self._drain_session(proc.pid)
        output, _ = proc.communicate(timeout=5)
        self.assertEqual([], survivors, f"clock failure leaked helpers: {survivors}")
        self.assertNotEqual(0, proc.returncode, output)
        summary_path = self.results_dir() / "cold_start.json"
        self.assertTrue(summary_path.exists(), "clock failure wrote no summary")
        summary = json.loads(summary_path.read_text())
        self.assertEqual("FAIL_CLEANUP", summary["verdict"])
        self.assertFalse(summary["cleanup_ok"])
        self.assertEqual(2, summary["completed"])
        self.assertEqual(2, summary["ok"])
        self.assertIn(
            "container-side termination could not be verified",
            summary["reasons"],
        )
        self.assertIn("monotonic clock unreadable during container removal", output)
        run = self.read_run_manifest()
        self.assertIsNotNone(run)
        self.assertEqual([run[0]], self.read_rm_manifest())
        self.assertEqual(run[0], summary["run_container"])
        self.assertEqual([], self.work_dir_contents())

    def test_reconcile_clock_failure_settles_helper(self):
        """Round 6 finding 2: a clock failure mid-reconcile settles the helper."""
        self.write_daemon_status()
        uptime = self.write_uptime_file()
        proc = self.popen_cold_start(
            "2",
            extra_env={
                "STUB_DOCKER_RUN_HANG": "1",
                "STUB_RECONCILE_INSPECT_HANG": "1",
                "COLD_START_UPTIME_PATH": str(uptime),
                "COLD_START_SETUP_TIMEOUT_SECS": "30",
                "COLD_START_CLEANUP_GRACE_SECS": "30",
            },
        )
        try:
            # Barrier 1: the creation committed but was never
            # acknowledged, so the interrupt lands mid-creation
            # deterministically.
            self.wait_for_manifest_lines("run-manifest.log", 1, timeout=10)
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            os.kill(proc.pid, signal.SIGTERM)
            # Barrier 2: the trap's reconcile dispatched and stalled, so
            # deleting the test-owned clock lands mid-await
            # deterministically.
            self.wait_for_manifest_lines("inspect-manifest.log", 1, timeout=10)
            uptime.unlink()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("script stalled after the clock failed mid-reconcile")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        # The script exits on its own; a discarded helper would survive
        # as a pipe-holding orphan, so drain the session (collecting the
        # leak evidence), SIGKILL any stragglers to release the pipes,
        # then collect the script's own output.
        survivors = self._drain_session(proc.pid)
        if survivors:
            self._kill_session(proc.pid, signal.SIGKILL)
            self._drain_session(proc.pid)
        output, _ = proc.communicate(timeout=5)
        self.assertEqual([], survivors, f"clock failure leaked helpers: {survivors}")
        self.assertEqual(143, proc.returncode, output)
        summary_path = self.results_dir() / "cold_start.json"
        self.assertTrue(summary_path.exists(), "interrupt wrote no terminal summary")
        summary = json.loads(summary_path.read_text())
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        self.assertEqual("SIGTERM", summary["signal"])
        self.assertFalse(summary["cleanup_ok"])
        self.assertIn(
            "container-side termination could not be verified",
            summary["reasons"],
        )
        self.assertIn("monotonic clock unreadable during run-container reconcile", output)
        self.assertIn("leaving it in place", output)
        # No removal was ever attempted: the identity check never confirmed.
        self.assertEqual([], self.read_rm_manifest())
        run = self.read_run_manifest()
        self.assertIsNotNone(run)
        self.assertEqual(run[0], summary["run_container"])
        self.assertEqual([], self.work_dir_contents())

    def test_clock_unreadable_at_startup(self):
        """Round 6 finding 2: a broken clock at birth refuses before any work."""
        self.write_daemon_status()
        outcome = self.run_cold_start(
            "2",
            extra_env={"COLD_START_UPTIME_PATH": str(self.root / "no-such-uptime")},
            bound=REJECT_BOUND_SECS,
        )
        self.assert_completed(outcome, REJECT_BOUND_SECS)
        self.assertEqual(2, outcome.returncode, outcome.output)
        self.assertIn("monotonic clock", outcome.output)
        self.assertFalse((self.results_dir() / "cold_start.json").exists())
        self.assert_no_container_touched()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def _assert_unverified_clock_removal(self, summary, output, hold_rm):
        # With no readable monotonic clock, immediate settlement can kill
        # the cleanup CLI before it reaches removal entry. Either observed
        # roster is valid; foreign or duplicate removals are never valid.
        self.assertFalse(summary["cleanup_ok"])
        self.assertIn(summary["verdict"], ("FAIL_WORKLOAD", "FAIL_CLEANUP"))
        self.assertIn("container-side termination could not be verified", summary["reasons"])
        self.assertIn("monotonic clock unreadable during container removal", output)
        run = self.read_run_manifest()
        self.assertIsNotNone(run)
        self.assertEqual(run[0], summary["run_container"])
        removed = self.read_rm_manifest()
        self.assertIn(removed, ([], [run[0]]))
        if hold_rm:
            # A stub held before entry must be killed, never allowed to
            # complete its removal operation after the failed bound read.
            self.assertEqual([], removed)

    def test_storm_clock_failure_publishes_terminal_summary(self):
        self._check_storm_clock_failure_publishes_terminal_summary()

    def test_storm_clock_failure_before_removal_entry(self):
        self._check_storm_clock_failure_publishes_terminal_summary(hold_rm=True)

    def _check_storm_clock_failure_publishes_terminal_summary(self, hold_rm=False):
        """Round 7 finding 1: a clock failure mid-storm still publishes JSON.

        The started-run contract promises a terminal summary for every
        started run; exiting 2 with no JSON breaks it.
        """
        self.write_daemon_status()
        uptime = self.write_uptime_file()
        proc = self.popen_cold_start(
            "1",
            extra_env={
                "STUB_PKCS11_MODE": "hang",
                "STUB_MARKER_DIR": str(self.container_tmp),
                "STUB_DOCKER_RM_PRE_ENTRY_HOLD": "1" if hold_rm else "0",
                "COLD_START_UPTIME_PATH": str(uptime),
            },
        )
        try:
            # Barrier: the hung worker entered its PKCS11 operation, so
            # the storm join is polling and the unlink lands mid-join.
            self.wait_for_markers(["entered-1"], timeout=10)
            self.assertIsNone(
                proc.poll(), "script exited before the clock was failed"
            )
            uptime.unlink()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("script stalled after the clock failed mid-storm")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        if survivors:
            self._kill_session(proc.pid, signal.SIGKILL)
            self._drain_session(proc.pid)
        output, _ = proc.communicate(timeout=5)
        self.assertEqual([], survivors, f"clock failure leaked helpers: {survivors}")
        summary_path = self.results_dir() / "cold_start.json"
        self.assertTrue(
            summary_path.exists(), "started run published no terminal summary"
        )
        self.assertEqual(1, proc.returncode, output)
        summary = json.loads(summary_path.read_text())
        self.assertEqual("FAIL_WORKLOAD", summary["verdict"])
        # Unmeasurable, not exceeded: the storm never proved a timeout.
        self.assertFalse(summary["workload_timeout"])
        self.assertEqual(0, summary["completed"])
        self.assertEqual(0, summary["ok"])
        self.assertEqual(0, summary["fail"])
        reasons = summary["reasons"]
        self.assertIn(
            "monotonic clock unreadable during storm join: "
            "storm bound could not be measured",
            reasons,
        )
        # The storm path falls into sampler stop with the clock still
        # broken, so the sampler latch fires too.
        self.assertIn(
            "monotonic clock unreadable during sampler join: "
            "sampler bound could not be measured",
            reasons,
        )
        self.assertNotIn("bound exceeded", " ".join(reasons))
        self.assertIn(
            "container-side termination could not be verified",
            reasons,
        )
        self.assertIn("monotonic clock unreadable", output)
        self._assert_unverified_clock_removal(summary, output, hold_rm)
        self.assertEqual([], self.work_dir_contents())

    def test_storm_entry_clock_failure_publishes_terminal_summary(self):
        self._check_storm_entry_clock_failure_publishes_terminal_summary()

    def test_storm_entry_clock_failure_before_removal_entry(self):
        self._check_storm_entry_clock_failure_publishes_terminal_summary(hold_rm=True)

    def _check_storm_entry_clock_failure_publishes_terminal_summary(self, hold_rm=False):
        """Round 7 finding 1 (entry site): a clock failure as the storm
        starts still publishes JSON — and proves the entry latch fired."""
        self.write_daemon_status()
        uptime = self.write_uptime_file()
        hold = self.container_tmp / "storm-entry-hold.open"
        proc = self.popen_cold_start(
            "1",
            extra_env={
                "STUB_PKCS11_MODE": "hang",
                "STUB_DOCKER_RM_PRE_ENTRY_HOLD": "1" if hold_rm else "0",
                "COLD_START_UPTIME_PATH": str(uptime),
                "COLD_START_STORM_ENTRY_HOLD_FILE": str(hold),
            },
        )
        try:
            # Barrier: the run is held after spawning, before the storm
            # bound is computed, so the unlink lands pre-entry
            # deterministically; releasing then forces the entry site.
            self.wait_for_hold_open(hold)
            self.assertIsNone(
                proc.poll(), "script exited before the clock was failed"
            )
            uptime.unlink()
            hold.unlink()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("script stalled after the clock failed at storm entry")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        if survivors:
            self._kill_session(proc.pid, signal.SIGKILL)
            self._drain_session(proc.pid)
        output, _ = proc.communicate(timeout=5)
        self.assertEqual([], survivors, f"clock failure leaked helpers: {survivors}")
        summary_path = self.results_dir() / "cold_start.json"
        self.assertTrue(
            summary_path.exists(), "started run published no terminal summary"
        )
        self.assertEqual(1, proc.returncode, output)
        summary = json.loads(summary_path.read_text())
        self.assertEqual("FAIL_WORKLOAD", summary["verdict"])
        self.assertFalse(summary["workload_timeout"])
        self.assertEqual(0, summary["completed"])
        reasons = summary["reasons"]
        self.assertIn(
            "monotonic clock unreadable during storm join: "
            "storm bound could not be measured",
            reasons,
        )
        self.assertIn(
            "monotonic clock unreadable during sampler join: "
            "sampler bound could not be measured",
            reasons,
        )
        self.assertNotIn("bound exceeded", " ".join(reasons))
        self.assertIn(
            "container-side termination could not be verified",
            reasons,
        )
        # Site proof: the entry diagnostic fired (then the loop site on
        # the first iteration, since the clock stays broken).
        self.assertIn("monotonic clock unreadable at storm start", output)
        self.assertIn("monotonic clock unreadable during storm join", output)
        self._assert_unverified_clock_removal(summary, output, hold_rm)
        self.assertEqual([], self.work_dir_contents())

    def test_sampler_clock_failure_publishes_terminal_summary(self):
        self._check_sampler_clock_failure_publishes_terminal_summary()

    def test_sampler_clock_failure_before_removal_entry(self):
        self._check_sampler_clock_failure_publishes_terminal_summary(hold_rm=True)

    def _check_sampler_clock_failure_publishes_terminal_summary(self, hold_rm=False):
        """Round 7 finding 1: a clock failure mid-sampler-stop still
        publishes JSON, with verdict precedence intact."""
        self.write_daemon_status()
        uptime = self.write_uptime_file()
        proc = self.popen_cold_start(
            "1",
            extra_env={
                "COLD_START_SAMPLE_INTERVAL": "7",
                "STUB_SLEEP_HANG_ON": "7",
                "STUB_DOCKER_RM_PRE_ENTRY_HOLD": "1" if hold_rm else "0",
                "COLD_START_UPTIME_PATH": str(uptime),
            },
        )
        try:
            # Barrier: sampler stop was entered (the run touched `stop`)
            # with the sampler hung, so the unlink lands mid-join.
            self.wait_for_work_file("stop")
            self.assertIsNone(
                proc.poll(), "script exited before the clock was failed"
            )
            uptime.unlink()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("script stalled after the clock failed mid-sampler")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        if survivors:
            self._kill_session(proc.pid, signal.SIGKILL)
            self._drain_session(proc.pid)
        output, _ = proc.communicate(timeout=5)
        self.assertEqual([], survivors, f"clock failure leaked helpers: {survivors}")
        summary_path = self.results_dir() / "cold_start.json"
        self.assertTrue(
            summary_path.exists(), "started run published no terminal summary"
        )
        self.assertEqual(1, proc.returncode, output)
        summary = json.loads(summary_path.read_text())
        # Precedence: the workload completed (PASS underneath), cleanup
        # is unverifiable with the clock broken, so FAIL_CLEANUP
        # outranks the sampler failure.
        self.assertEqual("FAIL_CLEANUP", summary["verdict"])
        self.assertFalse(summary["workload_timeout"])
        self.assertEqual(1, summary["completed"])
        self.assertEqual(1, summary["ok"])
        self.assertFalse(summary["sampler_ok"])
        self.assertTrue(summary["sampler_killed"])
        self.assertNotEqual(0, summary["sampler_exit"])
        self.assertFalse(summary["cleanup_ok"])
        reasons = summary["reasons"]
        self.assertIn(
            "monotonic clock unreadable during sampler join: "
            "sampler bound could not be measured",
            reasons,
        )
        # The latches are phase-specific: the storm ran on a valid clock.
        self.assertNotIn(
            "monotonic clock unreadable during storm join: "
            "storm bound could not be measured",
            reasons,
        )
        self.assertNotIn("bound exceeded", " ".join(reasons))
        self.assertIn(
            "container-side termination could not be verified",
            reasons,
        )
        self.assertIn("monotonic clock unreadable during sampler join", output)
        self._assert_unverified_clock_removal(summary, output, hold_rm)
        self.assertEqual([], self.work_dir_contents())

    def test_sampler_entry_clock_failure_publishes_terminal_summary(self):
        self._check_sampler_entry_clock_failure_publishes_terminal_summary()

    def test_sampler_entry_clock_failure_before_removal_entry(self):
        self._check_sampler_entry_clock_failure_publishes_terminal_summary(hold_rm=True)

    def _check_sampler_entry_clock_failure_publishes_terminal_summary(self, hold_rm=False):
        """Round 7 finding 1 (entry site): a clock failure as sampler
        stop starts still publishes JSON — and proves the entry latch."""
        self.write_daemon_status()
        uptime = self.write_uptime_file()
        hold = self.container_tmp / "sampler-entry-hold.open"
        proc = self.popen_cold_start(
            "1",
            extra_env={
                "COLD_START_SAMPLE_INTERVAL": "7",
                "STUB_SLEEP_HANG_ON": "7",
                "STUB_DOCKER_RM_PRE_ENTRY_HOLD": "1" if hold_rm else "0",
                "COLD_START_UPTIME_PATH": str(uptime),
                "COLD_START_SAMPLER_ENTRY_HOLD_FILE": str(hold),
            },
        )
        try:
            # Barrier: the run is held after touching `stop`, before the
            # sampler bound is computed (an unobservable window without
            # the hold), so the unlink lands pre-entry; releasing then
            # forces the entry site.
            self.wait_for_hold_open(hold)
            self.assertIsNone(
                proc.poll(), "script exited before the clock was failed"
            )
            uptime.unlink()
            hold.unlink()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("script stalled after the clock failed at sampler entry")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        if survivors:
            self._kill_session(proc.pid, signal.SIGKILL)
            self._drain_session(proc.pid)
        output, _ = proc.communicate(timeout=5)
        self.assertEqual([], survivors, f"clock failure leaked helpers: {survivors}")
        summary_path = self.results_dir() / "cold_start.json"
        self.assertTrue(
            summary_path.exists(), "started run published no terminal summary"
        )
        self.assertEqual(1, proc.returncode, output)
        summary = json.loads(summary_path.read_text())
        self.assertEqual("FAIL_CLEANUP", summary["verdict"])
        self.assertFalse(summary["workload_timeout"])
        self.assertEqual(1, summary["completed"])
        self.assertEqual(1, summary["ok"])
        self.assertFalse(summary["sampler_ok"])
        self.assertTrue(summary["sampler_killed"])
        self.assertFalse(summary["cleanup_ok"])
        reasons = summary["reasons"]
        self.assertIn(
            "monotonic clock unreadable during sampler join: "
            "sampler bound could not be measured",
            reasons,
        )
        self.assertNotIn(
            "monotonic clock unreadable during storm join: "
            "storm bound could not be measured",
            reasons,
        )
        self.assertNotIn("bound exceeded", " ".join(reasons))
        self.assertIn(
            "container-side termination could not be verified",
            reasons,
        )
        # Site proof: the entry diagnostic fired (then the loop site on
        # the first iteration, since the clock stays broken).
        self.assertIn("monotonic clock unreadable at sampler stop", output)
        self.assertIn("monotonic clock unreadable during sampler join", output)
        self._assert_unverified_clock_removal(summary, output, hold_rm)
        self.assertEqual([], self.work_dir_contents())

    def test_run_removal_interrupt_completes_removal(self):
        """Round 5 finding 2: the trap finishes a stalled removal."""
        self.write_daemon_status()
        proc = self.popen_cold_start(
            "2", extra_env={"STUB_DOCKER_RM_HANG": "once"}
        )
        try:
            # Barrier: the main-flow removal dispatched and stalled, so
            # the signal lands mid-removal deterministically.
            self.wait_for_manifest_lines("rm-manifest.log", 1, timeout=10)
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            os.kill(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("script ignored SIGTERM during run-container removal")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"interrupt leaked descendants: {survivors}")
        self.assertEqual(143, proc.returncode, output)
        summary_path = self.results_dir() / "cold_start.json"
        self.assertTrue(summary_path.exists(), "interrupt wrote no terminal summary")
        summary = json.loads(summary_path.read_text())
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        self.assertEqual("SIGTERM", summary["signal"])
        self.assertIn(
            "interrupted by SIGTERM during cleanup:container-remove",
            summary["reasons"],
        )
        self.assertTrue(summary["cleanup_ok"])
        run = self.read_run_manifest()
        self.assertIsNotNone(run)
        self.assertEqual([run[0], run[0]], self.read_rm_manifest())
        self.assertEqual(run[0], summary["run_container"])
        self.assertEqual([], self.work_dir_contents())

    def test_run_removal_interrupt_times_out(self):
        """Round 5 finding 2: a removal that never acks fails closed."""
        self.write_daemon_status()
        proc = self.popen_cold_start(
            "2",
            extra_env={
                "STUB_DOCKER_RM_HANG": "always",
                "COLD_START_CLEANUP_GRACE_SECS": "2",
            },
        )
        try:
            self.wait_for_manifest_lines("rm-manifest.log", 1, timeout=10)
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            os.kill(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("script ignored SIGTERM during run-container removal")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"interrupt leaked descendants: {survivors}")
        self.assertEqual(143, proc.returncode, output)
        summary_path = self.results_dir() / "cold_start.json"
        self.assertTrue(summary_path.exists(), "interrupt wrote no terminal summary")
        summary = json.loads(summary_path.read_text())
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        self.assertEqual("SIGTERM", summary["signal"])
        self.assertIn(
            "interrupted by SIGTERM during cleanup:container-remove",
            summary["reasons"],
        )
        self.assertFalse(summary["cleanup_ok"])
        self.assertIn(
            "container-side termination could not be verified",
            summary["reasons"],
        )
        self.assertEqual([], summary["unresolved_pids"])
        run = self.read_run_manifest()
        self.assertIsNotNone(run)
        self.assertEqual([run[0], run[0]], self.read_rm_manifest())
        self.assertEqual(run[0], summary["run_container"])
        self.assertEqual([], self.work_dir_contents())

    # NOTE (round 5): a committed-but-unacked removal retry was pinned
    # here until the native probe showed `docker rm -f` is idempotent
    # (absent removes exit 0): the trap-retry-after-commit path is then
    # identical to the covered once-hang path, so the separate
    # already-gone tolerance — and its test — were removed as
    # unnecessary. See record.md Round 5.

    def test_exit_cleanup_signal_settles_helpers(self):
        """Round 5 finding 2: a signal during exit cleanup settles helpers.

        Signal-trap cleanup neutralizes further signals (bounded
        completion), so a second signal can only land inside exit-trap
        cleanup — where it must settle in-flight helpers instead of
        orphaning them.
        """
        self.write_daemon_status()
        proc = self.popen_cold_start(
            "2",
            extra_env={
                "STUB_DOCKER_RUN_HANG": "1",
                "STUB_RECONCILE_INSPECT_HANG": "1",
                "COLD_START_SETUP_TIMEOUT_SECS": "2",
                "COLD_START_CLEANUP_GRACE_SECS": "30",
            },
        )
        try:
            # Barrier: the exit trap is inside reconcile (the identity
            # inspect dispatched and stalled), so the signal lands
            # mid-cleanup deterministically.
            self.wait_for_manifest_lines("inspect-manifest.log", 1, timeout=10)
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            os.kill(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("script ignored SIGTERM during exit-trap cleanup")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"interrupt leaked descendants: {survivors}")
        self.assertEqual(143, proc.returncode, output)
        summary_path = self.results_dir() / "cold_start.json"
        self.assertTrue(summary_path.exists(), "interrupt wrote no terminal summary")
        summary = json.loads(summary_path.read_text())
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        self.assertEqual("SIGTERM", summary["signal"])
        self.assertIn(
            "interrupted by SIGTERM during setup:run-container",
            summary["reasons"],
        )
        # The abandoned reconcile was never confirmed: fail closed, with
        # the helper verifiably settled (see the survivor drain above).
        self.assertFalse(summary["cleanup_ok"])
        self.assertIn(
            "container-side termination could not be verified",
            summary["reasons"],
        )
        # No removal was ever attempted: the identity check stalled first.
        self.assertEqual([], self.read_rm_manifest())
        run = self.read_run_manifest()
        self.assertIsNotNone(run)
        self.assertEqual(run[0], summary["run_container"])
        self.assertEqual([], self.work_dir_contents())

    def wait_for_hold_open(self, hold_path, timeout=15):
        """Block until the script announces a held accounting window."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if hold_path.read_text().splitlines():
                    return True
            except OSError:
                pass
            time.sleep(0.02)
        self.fail(f"hold file {hold_path.name} never opened")

    def test_exit_cleanup_signal_in_reconcile_gap_fails_closed(self):
        """Round 6 finding 3: a signal between reconcile and removal fails closed.

        The reconcile helper is reaped (no helper tracked) but the
        removal never dispatches, so helper-presence accounting would
        report a clean cleanup of a container that still exists.
        """
        self.write_daemon_status()
        hold = self.container_tmp / "cleanup-hold.open"
        proc = self.popen_cold_start(
            "2",
            extra_env={
                "STUB_DOCKER_RUN_HANG": "1",
                "COLD_START_SETUP_TIMEOUT_SECS": "2",
                "COLD_START_CLEANUP_HOLD_FILE": str(hold),
            },
        )
        try:
            # Barrier: the exit trap reconciled the hung creation (label
            # matched) and is holding the reconcile→removal gap, so the
            # signal lands with no helper tracked but the obligation open.
            self.wait_for_hold_open(hold)
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            os.kill(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("script ignored SIGTERM in the reconcile gap")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"interrupt leaked descendants: {survivors}")
        self.assertEqual(143, proc.returncode, output)
        summary_path = self.results_dir() / "cold_start.json"
        self.assertTrue(summary_path.exists(), "interrupt wrote no terminal summary")
        summary = json.loads(summary_path.read_text())
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        self.assertEqual("SIGTERM", summary["signal"])
        self.assertIn(
            "interrupted by SIGTERM during setup:run-container",
            summary["reasons"],
        )
        # Aim proof first: no removal was ever dispatched — the signal
        # landed in the gap, after the reconcile but before the removal.
        self.assertEqual([], self.read_rm_manifest())
        run = self.read_run_manifest()
        self.assertIsNotNone(run)
        self.assertEqual(run[0], summary["run_container"])
        self.assertFalse(summary["cleanup_ok"])
        self.assertIn(
            "container-side termination could not be verified",
            summary["reasons"],
        )
        self.assertEqual([], self.work_dir_contents())

    def test_exit_cleanup_signal_in_rm_accounting_gap_fails_closed(self):
        """Round 6 finding 3 (sibling): a signal between a failed removal
        and its accounting fails closed — the reaped helper is untracked
        but the obligation is still open."""
        self.write_daemon_status()
        hold = self.container_tmp / "cleanup-hold.open"
        proc = self.popen_cold_start(
            "2",
            extra_env={
                "STUB_DOCKER_RUN_HANG": "1",
                "STUB_DOCKER_RM_FAIL": "1",
                "COLD_START_SETUP_TIMEOUT_SECS": "2",
                "COLD_START_CLEANUP_HOLD_FILE": str(hold),
            },
        )
        try:
            # Barrier 1: the reconcile→removal gap opened first (it is
            # upstream); release it so the run proceeds to the removal.
            self.wait_for_hold_open(hold)
            hold.unlink()
            # Barrier 2: the removal attempt failed and the run is
            # holding between the reaped helper and its accounting.
            self.wait_for_hold_open(hold)
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            os.kill(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("script ignored SIGTERM in the rm-accounting gap")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"interrupt leaked descendants: {survivors}")
        self.assertEqual(143, proc.returncode, output)
        summary_path = self.results_dir() / "cold_start.json"
        self.assertTrue(summary_path.exists(), "interrupt wrote no terminal summary")
        summary = json.loads(summary_path.read_text())
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        self.assertEqual("SIGTERM", summary["signal"])
        self.assertIn(
            "interrupted by SIGTERM during setup:run-container",
            summary["reasons"],
        )
        # Aim proof first: exactly one removal attempt ran and failed —
        # the signal landed after the helper was reaped, before accounting.
        run = self.read_run_manifest()
        self.assertIsNotNone(run)
        self.assertEqual([run[0]], self.read_rm_manifest())
        self.assertEqual(run[0], summary["run_container"])
        self.assertFalse(summary["cleanup_ok"])
        self.assertIn(
            "container-side termination could not be verified",
            summary["reasons"],
        )
        self.assertEqual([], self.work_dir_contents())

    def test_exit_cleanup_signal_in_mismatch_gap_fails_closed(self):
        """Round 6 finding 3 (sibling): a signal between mismatch
        detection and its accounting fails closed — nothing is tracked
        but the dispatched creation is still open."""
        self.write_daemon_status()
        hold = self.container_tmp / "cleanup-hold.open"
        proc = self.popen_cold_start(
            "2",
            extra_env={
                "STUB_DOCKER_RUN_HANG": "1",
                "STUB_RUN_LABEL_MISMATCH": "1",
                "COLD_START_SETUP_TIMEOUT_SECS": "2",
                "COLD_START_CLEANUP_HOLD_FILE": str(hold),
            },
        )
        try:
            # Barrier: the exit trap detected the ownership-label
            # mismatch and is holding before recording it, so the signal
            # lands with no helper tracked but the obligation open.
            self.wait_for_hold_open(hold)
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            os.kill(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("script ignored SIGTERM in the mismatch gap")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"interrupt leaked descendants: {survivors}")
        self.assertEqual(143, proc.returncode, output)
        summary_path = self.results_dir() / "cold_start.json"
        self.assertTrue(summary_path.exists(), "interrupt wrote no terminal summary")
        summary = json.loads(summary_path.read_text())
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        self.assertEqual("SIGTERM", summary["signal"])
        self.assertIn(
            "interrupted by SIGTERM during setup:run-container",
            summary["reasons"],
        )
        # Aim proof first: a mismatched container is never removed — the
        # signal landed after detection, before the leave-in-place
        # accounting.
        self.assertEqual([], self.read_rm_manifest())
        run = self.read_run_manifest()
        self.assertIsNotNone(run)
        self.assertEqual(run[0], summary["run_container"])
        self.assertFalse(summary["cleanup_ok"])
        self.assertIn(
            "container-side termination could not be verified",
            summary["reasons"],
        )
        self.assertEqual([], self.work_dir_contents())

    def test_run_container_preserves_unrelated_processes(self):
        """Round 4 finding 2: the run never touches foreign processes."""
        self.write_daemon_status()
        marker = self.container_tmp / "stranger-termed"
        # A foreign lookalike: shim-shaped argv[0] (the shape the old
        # text selector would have killed) plus a live TERM trap, in
        # its own session so only a signal could reach it.
        foreign = subprocess.Popen(
            [
                "bash",
                "-c",
                f"exec -a spawn_one.sh bash -c \"trap 'touch {marker}' TERM; sleep 600\"",
            ],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(0.5)
            inner = None
            for entry in Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    raw = (entry / "cmdline").read_bytes()
                except OSError:
                    continue
                if b"spawn_one" in raw and b"sleep" in raw:
                    inner = int(entry.name)
                    break
            self.assertIsNotNone(inner, "foreign lookalike never appeared")
            outcome = self.run_cold_start("1")
            self.assert_cold_start_pass(outcome, RUN_BOUND_SECS, 1)
            self.assertFalse(marker.exists(), "run signalled a foreign process")
            try:
                os.kill(inner, 0)
            except OSError:
                self.fail("run killed a foreign process")
        finally:
            try:
                os.killpg(foreign.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            foreign.wait(timeout=5)

    def test_blind_reader_with_hung_workload_removes_run_container(self):
        """Round 4 findings 2-3: container authority needs no /proc."""
        self.write_daemon_status()
        outcome = self.run_cold_start(
            "2",
            extra_env={
                "COLD_START_STAT_READER": "false",
                "STUB_PKCS11_MODE": "hang",
                "COLD_START_STORM_TIMEOUT_SECS": "2",
            },
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertLess(outcome.elapsed, 15, outcome.output)
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        summary = self.read_summary("cold_start.json")
        # No rows exist, so the workload verdict leads. Host-side
        # cleanup is unverifiable (blind reader: the killed wrappers
        # join the unresolved set), but the run container is removed
        # authoritatively — removal needs no process enumeration.
        # Blindness also means no timeout claim: aliveness cannot be
        # confirmed, so the missing rows (not a timeout flag) carry it.
        self.assertEqual(
            "FAIL_WORKLOAD", summary["verdict"], json.dumps(summary, indent=1)
        )
        self.assertFalse(summary["workload_timeout"])
        self.assertFalse(summary["cleanup_ok"])
        self.assertGreater(len(summary["unresolved_pids"]), 0)
        self.assertIn(
            "owned process states could not be verified: /proc reads failed",
            summary["reasons"],
        )
        self.assertNotIn(
            "container-side termination could not be verified",
            summary["reasons"],
        )
        self.assert_owned_container_cycle()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_setup_hang_bounded(self):
        """Round 2 finding 3: hung setup steps fail closed under a bound."""
        self.write_daemon_status()
        cases = {
            "compose-up-hang": ({"STUB_COMPOSE_UP_HANG": "1"}, "none"),
            "provision-hang": ({"STUB_PROVISION_HANG": "1"}, "cycled"),
        }
        for name, (extra, container) in cases.items():
            with self.subTest(case=name):
                extra = dict(extra)
                extra["COLD_START_SETUP_TIMEOUT_SECS"] = "2"
                outcome = self.run_cold_start("2", extra_env=extra, bound=REJECT_BOUND_SECS)
                self.assert_completed(outcome, REJECT_BOUND_SECS)
                self.assertEqual(2, outcome.returncode, outcome.output)
                self.assertIn("timed out", outcome.output)
                self.assertFalse((self.results_dir() / "cold_start.json").exists())
                if container == "cycled":
                    self.assert_owned_container_cycle()
                else:
                    self.assert_no_container_touched()
                self.assert_no_survivors(outcome)
                self.assertEqual([], self.work_dir_contents())

    def test_signal_during_provision_cleans_up(self):
        """Round 2 finding 3: signals interrupt hung setup promptly."""
        self.write_daemon_status()
        proc = self.popen_cold_start(
            "2",
            extra_env={
                "STUB_PROVISION_HANG": "1",
                "COLD_START_SETUP_TIMEOUT_SECS": "30",
                "STUB_MARKER_DIR": str(self.container_tmp),
            },
        )
        try:
            self.wait_for_markers(["provision-entered"], timeout=10)
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            os.kill(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("script ignored SIGTERM during setup")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"interrupt leaked descendants: {survivors}")
        self.assertEqual([], self.work_dir_contents())
        self.assertEqual(143, proc.returncode, output)
        summary_path = self.results_dir() / "cold_start.json"
        self.assertTrue(summary_path.exists(), "interrupt wrote no terminal summary")
        summary = json.loads(summary_path.read_text())
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        self.assertEqual("SIGTERM", summary["signal"])
        # The run container already existed: the trap removed it.
        self.assert_owned_container_cycle()

    def test_invalid_counts_rejected(self):
        """Q09 box 2: empty/invalid N is a usage error, never a silent storm."""
        for bad in ("", "0", "-5", "abc", "3.5", "4 ", "1e2"):
            with self.subTest(n=bad):
                self.write_daemon_status()
                outcome = self.run_cold_start(bad, bound=REJECT_BOUND_SECS)
                self.assert_completed(outcome, REJECT_BOUND_SECS)
                self.assertEqual(2, outcome.returncode, outcome.output)
                self.assertIn("positive integer", outcome.output)
                self.assertFalse((self.results_dir() / "cold_start.json").exists())
                self.assert_no_container_touched()
                self.assert_no_survivors(outcome)
                self.assertEqual([], self.work_dir_contents())

    def test_setup_failures_fail_closed(self):
        """Q09 box 3: setup failures exit 2 with no fabricated summary."""
        self.write_daemon_status()
        cases = {
            # (extra env, expected output fragment, container expectation:
            # "none" = refused before any container existed, "cycled" =
            # the run container was created and trap-removed on exit).
            "compose-up": (
                {"STUB_COMPOSE_UP_FAIL": "1"},
                "cannot reach the daemon",
                "none",
            ),
            "provision": (
                {"STUB_PROVISION_FAIL": "1"},
                "stream reset by peer",
                "cycled",
            ),
            "inspect-fails": ({"STUB_INSPECT_FAIL": "1"}, None, "none"),
            "inspect-garbage": ({"STUB_INSPECT_OUTPUT": "not-a-pid"}, None, "none"),
            "inspect-empty": ({"STUB_INSPECT_OUTPUT": ""}, None, "none"),
            "inspect-zero": ({"STUB_INSPECT_OUTPUT": "0"}, None, "none"),
            "run-container": (
                {"STUB_DOCKER_RUN_FAIL": "1"},
                "cannot create run container",
                "none",
            ),
            "shell-inspect-fails": (
                {"STUB_SHELL_INSPECT_FAIL": "1"},
                None,
                "none",
            ),
            "shell-inspect-garbage-image": (
                {"STUB_SHELL_INSPECT_OUTPUT": "!!! not an image !!!"},
                None,
                "none",
            ),
            "shell-inspect-garbage-env": (
                {
                    "STUB_SHELL_INSPECT_OUTPUT": (
                        "stub-shell-image:latest\nNOT_AN_ENV_LINE"
                    )
                },
                None,
                "none",
            ),
        }
        for name, (extra, expect_output, container) in cases.items():
            with self.subTest(case=name):
                outcome = self.run_cold_start("2", extra_env=extra, bound=REJECT_BOUND_SECS)
                self.assert_completed(outcome, REJECT_BOUND_SECS)
                self.assertEqual(2, outcome.returncode, outcome.output)
                if expect_output is not None:
                    self.assertIn(expect_output, outcome.output)
                self.assertFalse((self.results_dir() / "cold_start.json").exists())
                if name == "run-container":
                    # Round 6 finding 1: the canonical "no such object"
                    # absence still clears quietly — no unverified warning.
                    self.assertNotIn("leaving it in place", outcome.output)
                    self.assertNotIn("may exist", outcome.output)
                if container == "cycled":
                    self.assert_owned_container_cycle()
                else:
                    self.assert_no_container_touched()
                self.assert_no_survivors(outcome)
                self.assertEqual([], self.work_dir_contents())

    def test_missing_top_tool_fails_closed(self):
        """Q09 box 3: a missing required tool is a setup error, not zero rows."""
        self.write_daemon_status()
        (self.bin / "top").unlink()
        outcome = self.run_cold_start("2", bound=REJECT_BOUND_SECS)
        self.assert_completed(outcome, REJECT_BOUND_SECS)
        self.assertEqual(2, outcome.returncode, outcome.output)
        self.assertIn("'top'", outcome.output)
        self.assertFalse((self.results_dir() / "cold_start.json").exists())
        self.assert_no_container_touched()
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_invalid_env_rejected(self):
        """Q09 box 3: invalid harness tuning is a usage error, not a guess."""
        self.write_daemon_status()
        cases = {
            "COLD_START_SETUP_TIMEOUT_SECS": ["", "abc", "-1"],
            "COLD_START_STORM_TIMEOUT_SECS": ["", "abc", "-1", "1.5"],
            "COLD_START_SAMPLER_TIMEOUT_SECS": ["xx"],
            "COLD_START_CLEANUP_GRACE_SECS": ["-2"],
            "COLD_START_SAMPLE_INTERVAL": ["", "0", "0.0", "-1", "abc"],
            "COLD_START_STARTUP_SLEEP": ["-1", "abc"],
            "COLD_START_PROC_ROOT": ["/nonexistent-proc-root-q09"],
        }
        for var, values in cases.items():
            for value in values:
                with self.subTest(var=var, value=value):
                    outcome = self.run_cold_start(
                        "2", extra_env={var: value}, bound=REJECT_BOUND_SECS
                    )
                    self.assert_completed(outcome, REJECT_BOUND_SECS)
                    self.assertEqual(2, outcome.returncode, outcome.output)
                    self.assertIn(var, outcome.output)
                    self.assertFalse((self.results_dir() / "cold_start.json").exists())
                    self.assert_no_container_touched()
                    self.assert_no_survivors(outcome)
                    self.assertEqual([], self.work_dir_contents())

    def test_no_unqualified_wait_and_signal_cleanup(self):
        """Q09 box 3 (static): explicit PID waits plus EXIT/INT/TERM traps."""
        source = COLD_START_SRC.read_text()
        violations = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            # Naive comment strip: wait sites carry no '#' inside strings.
            code = line.split("#", 1)[0]
            for match in re.finditer(r"(?:^|[;&|(\s])wait(?:\s|;|$|\)|\|)", code):
                rest = code[match.end():]
                if not re.match(r'\s*["$]', rest):
                    violations.append(f"{lineno}: {line.strip()}")
        self.assertEqual([], violations, "bare `wait` without explicit PIDs")
        trapped = set()
        for line in source.splitlines():
            code = line.split("#", 1)[0]
            match = re.search(r"^\s*trap\s+(.+)$", code)
            if not match:
                continue
            rest = match.group(1).strip()
            if rest[:1] in ("'", '"'):
                quote = rest[:1]
                end = rest.index(quote, 1)
                rest = rest[end + 1:].strip()
            else:
                rest = rest.split(None, 1)[1].strip() if len(rest.split(None, 1)) > 1 else ""
            trapped.update(rest.split())
        self.assertTrue(
            {"EXIT", "INT", "TERM"} <= trapped,
            f"missing signal traps; found: {sorted(trapped)}",
        )


SOAK_VERDICTS = {
    "PASS",
    "FAIL_WORKLOAD",
    "FAIL_RESULT",
    "FAIL_CLEANUP",
    "FAIL_RSS_GROWTH",
    "FAIL_FD_GROWTH",
    "FAIL_SAMPLER",
    "FAIL_INTERRUPTED",
}


class SoakHarnessTest(PerfHarnessCase):
    """Q10: fail-closed soak evidence (PERF-02)."""

    #: Soak-world donor shell: the real shell image sets
    #: PKCS11_MODULE_PATH (Dockerfile.consumer.shell ENV), so the soak
    #: base witnesses it (the Q09 default omits it).
    SOAK_SHELL_INSPECT_OUTPUT = (
        ColdStartHarnessTest.STUB_SHELL_IMAGE
        + "\n"
        + "\n".join(
            f"{key}={value}"
            for key, value in ColdStartHarnessTest.STUB_SHELL_ENV.items()
        )
        + "\nPKCS11_MODULE_PATH=/usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so"
    )
    #: Same donor without the shim path (module-unmeasurable control).
    SOAK_SHELL_INSPECT_NO_MODULE = (
        ColdStartHarnessTest.STUB_SHELL_IMAGE
        + "\n"
        + "\n".join(
            f"{key}={value}"
            for key, value in ColdStartHarnessTest.STUB_SHELL_ENV.items()
        )
    )

    def _clear_soak_results(self):
        for name in (
            "soak.json",
            "soak_samples.csv",
            "soak_daemon_samples.csv",
            "detached-manifest.log",
            "fd-seq.idx",
            "soakworker-manifest.log",
            "soakworker-exits.log",
            "rm-manifest.log",
            "inspect-manifest.log",
        ):
            try:
                (self.results_dir() / name).unlink()
            except OSError:
                pass
            try:
                (self.container_tmp / name).unlink()
            except OSError:
                pass
        # NOTE: container_tmp/soak_result.txt (the legacy fixed-name
        # result) is seed-managed by the stale test, never cleared here.

    def soak_base_env(self):
        # Test-world defaults: instant runs need no warmup exclusion
        # (production default is 300s), the donor shell carries the
        # image-set shim path like the real consumer-shell image, and
        # daemon RSS reads come from the fake proc tree.
        return {
            "DURATION": "1",
            "RPS": "1",
            "SOAK_WARMUP_SECS": "0",
            "SOAK_PROC_ROOT": str(self.fake_proc),
            "STUB_SHELL_INSPECT_OUTPUT": self.SOAK_SHELL_INSPECT_OUTPUT,
        }

    def stage_consumer_defaults(self):
        """Stage the shared consumer defaults the script sources."""
        source = ROOT / "tests" / "consumers" / "scripts" / "common.sh"
        staged = self.root / "tests" / "consumers" / "scripts" / "common.sh"
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(source.read_bytes())
        self.assertEqual(
            source.read_bytes(),
            staged.read_bytes(),
            "staged common.sh bytes must equal the committed bytes",
        )

    def run_soak(self, extra_env=None, bound=RUN_BOUND_SECS):
        self._clear_soak_results()
        script = self.stage_script(SOAK_SRC)
        self.stage_consumer_defaults()
        env = self.soak_base_env()
        env.update(extra_env or {})
        return self.run_bounded([BASH, str(script)], env, bound)

    def popen_soak(self, extra_env=None, clear_results=True):
        if clear_results:
            self._clear_soak_results()
        script = self.stage_script(SOAK_SRC)
        self.stage_consumer_defaults()
        env = self.base_env(self.soak_base_env())
        env.update(extra_env or {})
        proc = subprocess.Popen(
            [BASH, str(script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
            env=env,
        )
        self._tracked_sessions.append(proc.pid)
        return proc

    def read_valid_soak_summary(self):
        """Parse soak.json, failing loudly when it is missing/invalid."""
        summary_path = self.results_dir() / "soak.json"
        if not summary_path.exists():
            self.fail("soak run published no terminal summary")
        raw = summary_path.read_text()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            self.fail(f"soak summary is not valid JSON: {raw!r}")

    def assert_valid_soak_summary(self, summary):
        """Pin the soak-summary/1 schema (success and failure alike)."""
        self.assertIn("schema", summary)
        self.assertEqual("soak-summary/1", summary["schema"])
        for key in (
            "run_id",
            "duration_s",
            "target_rps",
            "warmup_s",
            "sample_interval_s",
            "worker_grace_s",
            "op_timeout_s",
            "limits",
            "identities",
            "worker",
            "offered",
            "counts",
            "completed",
            "completed_per_wall_s",
            "ok_per_wall_s",
            "completed_per_busy_s",
            "busy_ns",
            "wall_s",
            "samples",
            "ok_signs",
            "fail_signs",
            "initial_rss_kb",
            "final_rss_kb",
            "delta_rss_mb",
            "final_open_fds",
            "cleanup_ok",
            "unresolved_pids",
            "verdict",
            "reasons",
            "signal",
        ):
            self.assertIn(key, summary)
        self.assertIn(summary["verdict"], SOAK_VERDICTS)
        self.assertIsInstance(summary["reasons"], list)
        for key in ("max_rss_growth_mb", "max_fd_growth", "provenance"):
            self.assertIn(key, summary["limits"])
        for key in ("receipt_version", "mode", "provider", "workload"):
            self.assertIn(key, summary["identities"])
        for key in ("module", "image", "config_fingerprint"):
            self.assertIn(key, summary["identities"]["provider"])
        for key in ("revision", "corpus_hash"):
            self.assertIn(key, summary["identities"]["workload"])
        for key in ("exit", "acked", "complete", "result_run_id", "elapsed_s"):
            self.assertIn(key, summary["worker"])
        if summary["counts"] is not None:
            for key in (
                "success",
                "timeout",
                "error",
                "unknown",
                "unfinished",
                "censored",
                "total",
            ):
                value = summary["counts"][key]
                self.assertIsInstance(value, int)
                self.assertGreaterEqual(value, 0)
        for key in (
            "n",
            "n_warmup_excluded",
            "baseline",
            "final",
            "peak_rss_kb",
            "peak_fds",
        ):
            self.assertIn(key, summary["samples"])

    @staticmethod
    def _children_of(ppid):
        """PIDs whose parent is *ppid* (via /proc, no external tools)."""
        kids = []
        try:
            entries = os.listdir("/proc")
        except OSError:
            return kids
        for entry in entries:
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/stat") as handle:
                    content = handle.read()
            except OSError:
                continue
            rest = content.rsplit(") ", 1)
            if len(rest) != 2:
                continue
            fields = rest[1].split()
            if len(fields) >= 2 and fields[1] == str(ppid):
                kids.append(int(entry))
        return kids

    def wait_for_soak_worker_spawn(self, timeout=15):
        """Block until the owned worker spawn is recorded."""
        manifest = self.container_tmp / "soakworker-manifest.log"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                text = manifest.read_text()
            except OSError:
                text = ""
            if any(
                line.startswith("worker ") for line in text.splitlines()
            ):
                return
            time.sleep(0.02)
        self.fail("owned worker was never spawned")

    def wait_for_soak_result(self, timeout=30):
        """Block until the worker's terminal result file exists."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if list(self.container_tmp.glob("soak_result-*.txt")):
                return
            time.sleep(0.02)
        self.fail("worker result file never appeared")

    @staticmethod
    def _cmdline_contains(pid, fragment):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as handle:
                content = handle.read()
        except OSError:
            return False
        return fragment.encode() in content

    @staticmethod
    def _cmdline_argv(pid):
        """Argv of a process (None when unreadable, [] when empty)."""
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as handle:
                content = handle.read()
        except OSError:
            return None
        if not content:
            return []
        return content.rstrip(b"\x00").decode("utf-8", "replace").split("\x00")

    @staticmethod
    def _stat_state(pid):
        """Process state letter from /proc/PID/stat (None when unreadable)."""
        try:
            with open(f"/proc/{pid}/stat") as handle:
                content = handle.read()
        except OSError:
            return None
        rest = content.rsplit(") ", 1)
        if len(rest) != 2:
            return None
        fields = rest[1].split()
        if fields:
            return fields[0]
        return None

    @classmethod
    def _pid_dead(cls, pid):
        """True when *pid* is gone or a reaped-pending zombie."""
        return cls._stat_state(pid) in (None, "Z")

    def _worker_subshell_pids(self, controller):
        """Controller children whose CLI serves the soak worker.

        Identity (a descendant command line containing the worker
        path), not shape: sample helpers have children too, and must
        never be selected.
        """
        found = []
        for kid in self._children_of(controller):
            stack = list(self._children_of(kid))
            while stack:
                current = stack.pop()
                if self._cmdline_contains(current, "soak_worker.sh"):
                    found.append(kid)
                    break
                stack.extend(self._children_of(current))
        return found

    def wait_for_soak_checkpoint(self, timeout=30):
        """Block until a partial (complete:false) checkpoint has work."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for path in self.container_tmp.glob("soak_result-*.txt"):
                try:
                    record = json.loads(path.read_text())
                except (OSError, ValueError):
                    continue
                if record.get("complete") is False and (
                    record.get("offered") or 0
                ) > 0:
                    return
            time.sleep(0.02)
        self.fail("worker checkpoint never appeared")

    def wait_for_soak_checkpoint_record(self, timeout=30):
        """Block until a partial checkpoint has work; return its record.

        The record is a whole atomic write (the worker renames a tmp
        file per op), but the worker keeps advancing: callers must
        compare monotonically (>=), never exactly.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for path in sorted(self.container_tmp.glob("soak_result-*.txt")):
                try:
                    record = json.loads(path.read_text())
                except (OSError, ValueError):
                    continue
                if record.get("complete") is False and (
                    record.get("offered") or 0
                ) > 0:
                    return record
            time.sleep(0.02)
        self.fail("worker checkpoint never appeared")

    def wait_for_soak_ack_recorded(self, timeout=30):
        """Block until the worker's acknowledgement file exists.

        The done-file itself — not a childlessness proxy (a subshell
        can be childless yet suspended before its write, so no
        process-state poll can prove the write landed).
        """
        return self.wait_for_work_file("worker.done", timeout=timeout)

    def wait_for_container_file(self, name, timeout=15):
        """Block until container_tmp holds *name* (hold arrivals)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if (self.container_tmp / name).exists():
                return
            time.sleep(0.02)
        self.fail(f"container file {name} never appeared")

    def _kill_soak_orphans(self, sid):
        """SIGKILL worker-tree orphans by manifest PID + cmdline scan."""
        targets = set()
        for line in self.read_soakworker_manifest():
            if len(line) == 2 and line[0] == "worker":
                try:
                    targets.add(int(line[1]))
                except ValueError:
                    pass
        try:
            entries = os.listdir("/proc")
        except OSError:
            entries = []
        for entry in entries:
            if not entry.isdigit():
                continue
            pid = int(entry)
            if self._cmdline_contains(
                pid, os.path.join(str(self.container_tmp), "soak_worker.sh")
            ):
                targets.add(pid)
                targets.update(self._children_of(pid))
        for pid in self._children_of(os.getpid()):
            targets.discard(pid)
        for pid in sorted(targets):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not session_members(sid):
                return
            time.sleep(0.02)

    def wait_for_soak_samples(self, count, timeout=15):
        """Block until soak_samples.csv holds >= count data rows."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                rows = self.read_csv_rows("soak_samples.csv")
            except OSError:
                rows = []
            if len(rows) - 1 >= count:
                return rows
            time.sleep(0.02)
        self.fail(f"soak_samples.csv never reached {count} data rows")

    def read_soakworker_manifest(self):
        manifest = self.container_tmp / "soakworker-manifest.log"
        if not manifest.exists():
            return []
        return [
            line.split()
            for line in manifest.read_text().splitlines()
            if line.split()
        ]

    def write_legacy_seed(self, text="ok=999 fail=0\n"):
        path = self.container_tmp / "soak_result.txt"
        path.write_text(text)
        return path

    def drain_collect(self, proc):
        """Wait for exit, drain pipe-holding strays, collect output."""
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self._kill_session(proc.pid, signal.SIGKILL)
            proc.communicate(timeout=5)
            self.fail("soak run stalled")
        survivors = self._drain_session(proc.pid)
        if survivors:
            self._kill_session(proc.pid, signal.SIGKILL)
            self._drain_session(proc.pid)
        output, _ = proc.communicate(timeout=5)
        return survivors, output

    def test_soak_all_fail_reports_non_success(self):
        """Q10 Box 1: the review's all-fail/PASS reproduction."""
        self.write_daemon_status()
        outcome = self.run_soak(
            extra_env={
                "STUB_SOAK_LEGACY_RESULT": "fail20",
                "STUB_PKCS11_MODE": "fail",
            },
            bound=RUN_BOUND_SECS,
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        raw = (self.results_dir() / "soak.json").read_text()
        summary = json.loads(raw)
        # Fault proof: failures really occurred.
        self.assertGreater(summary["fail_signs"], 0)
        self.assertNotEqual(0, outcome.returncode, f"all-fail run passed: {raw}")
        self.assertNotEqual("PASS", summary["verdict"])
        self.assertEqual("FAIL_WORKLOAD", summary["verdict"])
        self.assert_valid_soak_summary(summary)
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_missing_result_fails_closed(self):
        """Q10 Box 1: the review's missing-result/invalid-JSON reproduction."""
        self.write_daemon_status()
        cases = {
            "missing": {"STUB_SOAK_RESULT_MODE": "missing"},
            "read-hang": {
                "STUB_SOAK_RESULT_HANG": "1",
                "SOAK_SAMPLE_TIMEOUT_SECS": "2",
            },
        }
        for name, extra in cases.items():
            with self.subTest(case=name):
                extra = dict(extra)
                extra["STUB_SOAK_LEGACY_RESULT"] = "missing"
                outcome = self.run_soak(extra_env=extra, bound=RUN_BOUND_SECS)
                self.assert_completed(outcome, RUN_BOUND_SECS)
                summary = self.read_valid_soak_summary()
                self.assertNotEqual(0, outcome.returncode, outcome.output)
                self.assertEqual("FAIL_RESULT", summary["verdict"])
                self.assertIn("result", " ".join(summary["reasons"]))
                self.assert_valid_soak_summary(summary)
                self.assert_no_survivors(outcome)
                self.assertEqual([], self.work_dir_contents())

    def test_soak_invalid_result_fails_closed(self):
        """Q10 Box 1: an unparseable result fails closed with valid JSON."""
        self.write_daemon_status()
        outcome = self.run_soak(
            extra_env={
                "STUB_SOAK_LEGACY_RESULT": "garbage",
                "STUB_SOAK_RESULT_MODE": "malformed",
            },
            bound=RUN_BOUND_SECS,
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        summary = self.read_valid_soak_summary()
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        self.assertEqual("FAIL_RESULT", summary["verdict"])
        self.assert_valid_soak_summary(summary)
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_stale_result_fails_closed(self):
        """Q10 Box 1: a previous run's result never yields success."""
        self.write_daemon_status()
        self.write_legacy_seed()
        outcome = self.run_soak(
            extra_env={
                "STUB_SOAK_LEGACY_RESULT": "seeded",
                "STUB_SOAK_RESULT_MODE": "stale-id",
            },
            bound=RUN_BOUND_SECS,
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        summary = self.read_valid_soak_summary()
        # The stale seed (ok=999) must never be consumed.
        self.assertNotEqual(
            999, summary["ok_signs"], "stale seed was consumed as current"
        )
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        self.assertEqual("FAIL_RESULT", summary["verdict"])
        # The observed foreign run id is recorded for debugging.
        self.assertEqual("soak-stale-000", summary["worker"]["result_run_id"])
        self.assert_valid_soak_summary(summary)
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_no_completed_work_fails_closed(self):
        """Q10 Box 1: zero offered operations is not a pass."""
        self.write_daemon_status()
        outcome = self.run_soak(
            extra_env={
                "DURATION": "0",
                "STUB_SOAK_LEGACY_RESULT": "empty",
            },
            bound=RUN_BOUND_SECS,
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        summary = self.read_valid_soak_summary()
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        self.assertEqual("FAIL_WORKLOAD", summary["verdict"])
        self.assertEqual(0, summary["offered"])
        self.assertEqual(0, summary["completed"])
        self.assert_valid_soak_summary(summary)
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_unfinished_worker_fails_closed(self):
        """Q10 Box 1: a worker that never acknowledges fails closed."""
        self.write_daemon_status()
        outcome = self.run_soak(
            extra_env={
                "STUB_PKCS11_MODE": "hang",
                "STUB_SOAK_LEGACY_RESULT": "missing",
                "SOAK_WORKER_GRACE_SECS": "2",
                "SOAK_OP_TIMEOUT_SECS": "30",
            },
            bound=RUN_BOUND_SECS,
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        summary = self.read_valid_soak_summary()
        self.assertEqual("FAIL_WORKLOAD", summary["verdict"])
        self.assertIn("unfinished", " ".join(summary["reasons"]))
        self.assertFalse(summary["worker"]["acked"])
        self.assert_valid_soak_summary(summary)
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_rss_growth_exceeding_limit_fails(self):
        """Q10 Box 1: RSS growth over the limit fails with nonzero exit."""
        # Baseline is the 123456 kB stub status (median of the first
        # five rows); the rewrite lands after the whole baseline
        # window. The boundary cases pin exact-KiB comparison: an
        # MB-truncating verdict would pass both.
        cases = {
            # (184896-123456)/1024 = 60 MB over a 50 MB limit.
            "over": ("50", 184896, 60),
            # 51201 KiB over a 50 MB limit: one KiB past the line
            # (truncation reads 50 MB and passes).
            "limit-plus-one-kib": ("50", 123456 + 50 * 1024 + 1, 50),
            # 512 KiB over a zero limit (truncation reads 0 and passes).
            "zero-limit": ("0", 123456 + 512, 0),
        }
        for name, (limit, grown, delta) in cases.items():
            with self.subTest(case=name):
                self.write_daemon_status()
                proc = self.popen_soak(
                    extra_env={
                        "DURATION": "3",
                        "STUB_SOAK_LEGACY_RESULT": "empty",
                        "SOAK_MAX_RSS_GROWTH_MB": limit,
                    },
                )
                try:
                    # Barrier: six samples in, so the rewrite lands
                    # after the whole five-row baseline window (a
                    # smaller barrier would contaminate the baseline
                    # median with grown rows).
                    self.wait_for_soak_samples(6)
                    self.assertIsNone(
                        proc.poll(), "script exited before RSS was grown"
                    )
                    status = self.fake_proc / self.daemon_pid / "status"
                    status.write_text(f"Name:\tdaemon\nVmRSS:\t {grown} kB\n")
                    survivors, output = self.drain_collect(proc)
                finally:
                    if proc.poll() is None:
                        self._kill_session(proc.pid, signal.SIGKILL)
                        proc.communicate(timeout=5)
                self.assertEqual(
                    [], survivors, f"soak leaked helpers: {survivors}"
                )
                summary = self.read_valid_soak_summary()
                # The displayed delta stays an MB floor; the verdict
                # compares exact KiB.
                self.assertEqual(delta, summary["delta_rss_mb"])
                self.assertEqual("FAIL_RSS_GROWTH", summary["verdict"])
                self.assertNotEqual(0, proc.returncode, output)
                self.assert_valid_soak_summary(summary)
                self.assertEqual([], self.work_dir_contents())

    def test_soak_fd_growth_exceeding_limit_fails(self):
        """Q10 Box 1: FD growth over the limit fails with nonzero exit."""
        self.write_daemon_status()
        outcome = self.run_soak(
            extra_env={
                "DURATION": "2",
                "STUB_SOAK_LEGACY_RESULT": "empty",
                "STUB_SOAK_FD_SEQ": "10,10,10,10,60",
                "SOAK_MAX_FD_GROWTH": "20",
            },
            bound=RUN_BOUND_SECS,
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        summary = self.read_valid_soak_summary()
        self.assertNotEqual("PASS", summary["verdict"])
        self.assertEqual("FAIL_FD_GROWTH", summary["verdict"])
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        # Growth math pinned from the reported windows: 60-10.
        self.assertEqual(
            50,
            summary["samples"]["final"]["fds"]
            - summary["samples"]["baseline"]["fds"],
        )
        self.assert_valid_soak_summary(summary)
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_unmeasurable_daemon_refuses_before_work(self):
        """Q10 Box 1: an unmeasurable daemon refuses before any work."""
        cases = {
            "rss-absent": (False, {}),
            "rss-empty": (False, {"SOAK_RSS_EMPTY": "1"}),
            "fd-refused": (True, {"STUB_SOAK_FD_FAIL": "1"}),
            "module-missing": (
                True,
                {
                    "STUB_SHELL_INSPECT_OUTPUT": (
                        self.SOAK_SHELL_INSPECT_NO_MODULE
                    )
                },
            ),
        }
        for name, (write_status, extra) in cases.items():
            with self.subTest(case=name):
                if write_status:
                    self.write_daemon_status()
                elif extra.pop("SOAK_RSS_EMPTY", None) is not None:
                    # Readable status with no usable VmRSS line: the
                    # gate must measure, not just check readability.
                    target = self.fake_proc / self.daemon_pid / "status"
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text("Name:\tsoak-daemon\nState:\tR\n")
                else:
                    target = self.fake_proc / self.daemon_pid / "status"
                    try:
                        target.unlink()
                    except OSError:
                        pass
                extra = dict(extra)
                extra["STUB_SOAK_LEGACY_RESULT"] = "empty"
                outcome = self.run_soak(extra_env=extra, bound=REJECT_BOUND_SECS)
                self.assert_completed(outcome, REJECT_BOUND_SECS)
                self.assertEqual(2, outcome.returncode, outcome.output)
                self.assertFalse((self.results_dir() / "soak.json").exists())
                self.assertEqual([], self.read_rm_manifest())
                self.assertEqual([], self.read_soakworker_manifest())
                self.assert_no_survivors(outcome)
                self.assertEqual([], self.work_dir_contents())

    def test_soak_unmeasurable_image_nulls_identity(self):
        """Q10 Box 3: a refused image inspect nulls the identity, not the run."""
        self.write_daemon_status()
        outcome = self.run_soak(
            extra_env={
                "STUB_SOAK_LEGACY_RESULT": "empty",
                "STUB_IMAGE_INSPECT_FAIL": "1",
            },
            bound=RUN_BOUND_SECS,
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        summary = self.read_valid_soak_summary()
        # Descriptive-only gap: the run is valid, comparability suffers.
        self.assertEqual("PASS", summary["verdict"])
        self.assertEqual(0, outcome.returncode, outcome.output)
        self.assertIsNone(summary["identities"]["provider"]["image"])
        self.assertIsNone(
            summary["identities"]["provider"]["config_fingerprint"]
        )
        self.assertIn("image", " ".join(summary["reasons"]))
        self.assert_valid_soak_summary(summary)
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_midrun_rss_loss_fails_sampler(self):
        """Q10 Box 1: RSS lost mid-run fails the sampler dimension."""
        self.write_daemon_status()
        proc = self.popen_soak(
            extra_env={
                "DURATION": "3",
                "STUB_SOAK_LEGACY_RESULT": "empty",
            },
        )
        try:
            # Barrier: one sample read, so at least one usable row
            # exists; everything after the delete is unavailable.
            self.wait_for_soak_samples(1)
            self.assertIsNone(
                proc.poll(), "script exited before RSS was lost"
            )
            (self.fake_proc / self.daemon_pid / "status").unlink()
            survivors, output = self.drain_collect(proc)
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        self.assertEqual([], survivors, f"soak leaked helpers: {survivors}")
        summary = self.read_valid_soak_summary()
        self.assertNotEqual("PASS", summary["verdict"])
        self.assertEqual("FAIL_SAMPLER", summary["verdict"])
        self.assertNotEqual(0, proc.returncode, output)
        # The final window has no usable row, while the last usable
        # read is preserved (not zeroed, not dropped).
        self.assertIsNone(summary["samples"]["final"]["rss_kb"])
        self.assertEqual(123456, summary["final_rss_kb"])
        self.assert_valid_soak_summary(summary)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_midrun_fd_loss_fails_sampler(self):
        """Q10 Box 1: FDs lost mid-run fail the sampler dimension."""
        self.write_daemon_status()
        outcome = self.run_soak(
            extra_env={
                "DURATION": "3",
                "STUB_SOAK_LEGACY_RESULT": "empty",
                "STUB_SOAK_FD_SEQ": "42,42,FAIL",
            },
            bound=RUN_BOUND_SECS,
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        summary = self.read_valid_soak_summary()
        self.assertNotEqual("PASS", summary["verdict"])
        self.assertEqual("FAIL_SAMPLER", summary["verdict"])
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        # The final window has no usable row, while the last usable
        # read is preserved (not zeroed, not dropped).
        self.assertIsNone(summary["samples"]["final"]["fds"])
        self.assertEqual(42, summary["final_open_fds"])
        self.assert_valid_soak_summary(summary)
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_removal_failure_fails_cleanup(self):
        """Q10 Box 1: a worker container that cannot be removed fails cleanup."""
        self.write_daemon_status()
        outcome = self.run_soak(
            extra_env={
                "STUB_SOAK_LEGACY_RESULT": "empty",
                "STUB_DOCKER_RM_FAIL": "1",
            },
            bound=RUN_BOUND_SECS,
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        # Cleanup proof first: an owned removal was attempted.
        self.assertNotEqual([], self.read_rm_manifest())
        summary = self.read_valid_soak_summary()
        self.assertEqual("FAIL_CLEANUP", summary["verdict"])
        self.assertFalse(summary["cleanup_ok"])
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        self.assert_valid_soak_summary(summary)
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_retirement_failure_fails_result_closed(self):
        """Q10 Box 2: a worker that cannot be retired fails closed."""
        self.write_daemon_status()
        outcome = self.run_soak(
            extra_env={
                "STUB_SOAK_LEGACY_RESULT": "empty",
                "STUB_DOCKER_STOP_FAIL": "1",
            },
            bound=RUN_BOUND_SECS,
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        summary = self.read_valid_soak_summary()
        # The worker finished and acked, but retirement failed, so no
        # result is read from the live filesystem: outcomes stay null,
        # honestly unavailable — never read live.
        self.assertEqual("FAIL_RESULT", summary["verdict"])
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        self.assertTrue(summary["worker"]["acked"])
        self.assertIsNone(summary["offered"])
        self.assertIsNone(summary["counts"])
        self.assertIn("retire", " ".join(summary["reasons"]))
        self.assert_valid_soak_summary(summary)
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_retirement_hang_bounded(self):
        """Q10 Box 2: a hung retirement fails closed under its bound."""
        self.write_daemon_status()
        outcome = self.run_soak(
            extra_env={
                "STUB_SOAK_LEGACY_RESULT": "empty",
                "STUB_DOCKER_STOP_HANG": "1",
                "SOAK_CLEANUP_GRACE_SECS": "1",
            },
            bound=RUN_BOUND_SECS,
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        summary = self.read_valid_soak_summary()
        self.assertEqual("FAIL_RESULT", summary["verdict"])
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        self.assertTrue(summary["worker"]["acked"])
        self.assertIsNone(summary["offered"])
        self.assertIsNone(summary["counts"])
        self.assertIn("retire", " ".join(summary["reasons"]))
        self.assert_valid_soak_summary(summary)
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_sample_wait_hang_fails_sampler_bounded(self):
        """Q10 Box 2: a stalled sample wait fails the sampler under its bound."""
        self.write_daemon_status()
        outcome = self.run_soak(
            extra_env={
                "DURATION": "5",
                "STUB_SOAK_LEGACY_RESULT": "empty",
                "SOAK_SAMPLE_INTERVAL_SECS": "2",
                "STUB_SLEEP_HANG_ON": "2",
                "SOAK_CLEANUP_GRACE_SECS": "1",
            },
            bound=RUN_BOUND_SECS,
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        summary = self.read_valid_soak_summary()
        self.assertEqual("FAIL_SAMPLER", summary["verdict"])
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        self.assertIn("sample wait", " ".join(summary["reasons"]))
        # The worker finished underneath (its outcomes stay valid);
        # only the cadence broke.
        self.assertTrue(summary["worker"]["acked"])
        self.assertGreater(summary["completed"], 0)
        self.assert_valid_soak_summary(summary)
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_interrupt_publishes_terminal_record(self):
        """Q10 Box 1: SIGTERM mid-soak publishes a terminal record."""
        self.write_daemon_status()
        proc = self.popen_soak(
            extra_env={
                "DURATION": "30",
                "STUB_SOAK_LEGACY_RESULT": "empty",
            },
        )
        try:
            self.wait_for_soak_samples(2, timeout=10)
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            os.kill(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("soak run ignored SIGTERM")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"interrupt leaked helpers: {survivors}")
        self.assertEqual(143, proc.returncode, output)
        summary = self.read_valid_soak_summary()
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        self.assertEqual("SIGTERM", summary["signal"])
        self.assertIn("interrupted by SIGTERM", " ".join(summary["reasons"]))
        # The owned worker container was still removed under signal.
        self.assertNotEqual([], self.read_rm_manifest())
        self.assert_valid_soak_summary(summary)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_interrupt_before_validation_carries_checkpoint(self):
        """Q10 Box 3: SIGTERM before validation carries checkpointed outcomes."""
        self.write_daemon_status()
        proc = self.popen_soak(
            extra_env={
                # The worker's window is time-based: it cannot ack
                # before 30s, so a prompt signal is structurally
                # pre-validation (validation needs the ack).
                "DURATION": "30",
                "STUB_SOAK_LEGACY_RESULT": "empty",
            },
        )
        try:
            observed = self.wait_for_soak_checkpoint_record(timeout=30)
            # The ack is still absent: this is the pre-validation
            # path (29s margin — the worker acks at 30s).
            self.assertEqual(
                [],
                sorted(self.work_tmp.glob("tmp.*/worker.done")),
                "worker acked before the interrupt (not pre-validation)",
            )
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            os.kill(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("soak run ignored SIGTERM")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"interrupt leaked helpers: {survivors}")
        self.assertEqual(143, proc.returncode, output)
        summary = self.read_valid_soak_summary()
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        self.assertEqual("SIGTERM", summary["signal"])
        # Carried, never null: the frozen checkpoint's cumulative
        # counts (>= — the worker advances between observation and
        # the trap's stop+copy). The run id pins the lineage: these
        # outcomes came from the observed checkpoint's file.
        self.assertFalse(summary["worker"]["complete"])
        self.assertEqual(
            observed["run_id"], summary["worker"]["result_run_id"]
        )
        self.assertIsNotNone(summary["offered"])
        self.assertIsNotNone(summary["counts"])
        self.assertGreaterEqual(summary["offered"], observed["offered"])
        self.assertGreaterEqual(
            summary["counts"]["success"], observed["counts"]["success"]
        )
        self.assertGreaterEqual(
            summary["completed"], observed["counts"]["success"]
        )
        self.assertGreaterEqual(
            summary["ok_signs"], observed["counts"]["success"]
        )
        obs_bad = (
            observed["counts"]["timeout"]
            + observed["counts"]["error"]
            + observed["counts"]["unknown"]
        )
        self.assertEqual(obs_bad, summary["fail_signs"])
        self.assertIn("partial checkpoint", " ".join(summary["reasons"]))
        self.assert_valid_soak_summary(summary)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_interrupted_run_overwrites_stale_summary(self):
        """Q10 Box 1: a stale summary never suppresses the terminal record."""
        self.write_daemon_status()
        # Seeded BEFORE spawn (after the helper's own clear): a
        # previous run's PASS sitting in the reused output directory.
        # Post-spawn seeding would race the run's startup removal
        # (R3 M2) — the seed could land after the removal and suppress
        # publication depending on scheduling. Pre-spawn the order is
        # total: seed, spawn, removal deletes the seed, the run
        # publishes its own terminal record.
        self._clear_soak_results()
        self.results_dir().mkdir(parents=True, exist_ok=True)
        (self.results_dir() / "soak.json").write_text(
            json.dumps(
                {
                    "schema": "soak-summary/1",
                    "verdict": "PASS",
                    "run_id": "soak-stale-seed",
                }
            )
        )
        proc = self.popen_soak(
            extra_env={
                "DURATION": "30",
                "STUB_SOAK_LEGACY_RESULT": "empty",
            },
            clear_results=False,
        )
        try:
            self.wait_for_soak_samples(2, timeout=10)
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            os.kill(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("soak run ignored SIGTERM")
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"interrupt leaked helpers: {survivors}")
        self.assertEqual(143, proc.returncode, output)
        summary = self.read_valid_soak_summary()
        # This run's terminal record, not the seeded PASS: startup
        # removal deleted the seed, so the trap's existence guard saw
        # no foreign summary and published.
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        self.assertNotEqual("soak-stale-seed", summary["run_id"])
        self.assert_valid_soak_summary(summary)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_interrupt_during_sample_sleep_is_prompt(self):
        """Q10 Box 2: SIGTERM during the sample wait answers at once."""
        self.write_daemon_status()
        proc = self.popen_soak(
            extra_env={
                "DURATION": "30",
                "STUB_SOAK_LEGACY_RESULT": "empty",
                # Real sleep durations: the capped stub would hide a
                # foreground-wait trap delay.
                "STUB_SLEEP_NOCAP": "1",
                "SOAK_SAMPLE_INTERVAL_SECS": "30",
            },
        )
        try:
            # Barrier, arrival-exact: one row landed (sampling phase,
            # never setup) and the SPECIFIC interval sleep announced
            # itself (its pidfile) and reached its wait. Each
            # conjunct is load-bearing: the pidfile names the exact
            # wait (a child scan would match await-loop poll sleeps
            # — R3 M3); the post-exec stub argv with the interval arg
            # excludes the pre-exec announcer ("_", "30") and poll
            # sleeps (stub, "0.05"); state S means inside time.sleep
            # (the stub's only blocking call), closing the ~1ms
            # post-exec startup gap.
            self.wait_for_soak_samples(1, timeout=10)
            pidfile = self.wait_for_work_file("sample-sleep.pid", timeout=15)
            stub_sleep = str(self.bin / "sleep")
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    announced = int(pidfile.read_text().strip())
                except (OSError, ValueError):
                    announced = None
                if announced is not None:
                    argv = self._cmdline_argv(announced)
                    if (
                        argv is not None
                        and len(argv) >= 2
                        and argv[-2] == stub_sleep
                        and argv[-1] == "30"
                        and self._stat_state(announced) == "S"
                    ):
                        break
                time.sleep(0.02)
            else:
                self.fail("interval sleep never reached its wait")
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            started = time.monotonic()
            os.kill(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("soak run ignored SIGTERM during the sample wait")
            answered = time.monotonic() - started
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        # Prompt means bounded escalation, not the 30s wait (15s
        # communicate bound with wide margin either way).
        self.assertLess(answered, 15, "SIGTERM waited out the sample sleep")
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"interrupt leaked helpers: {survivors}")
        self.assertEqual(143, proc.returncode, output)
        summary = self.read_valid_soak_summary()
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        self.assert_valid_soak_summary(summary)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_blind_interrupt_during_sample_sleep_reaps_wait(self):
        """Q10 Box 2 (R4 finding 1): blind settlement never orphans the wait."""
        self.write_daemon_status()
        proc = self.popen_soak(
            extra_env={
                "DURATION": "30",
                "STUB_SOAK_LEGACY_RESULT": "empty",
                "STUB_SLEEP_NOCAP": "1",
                "SOAK_SAMPLE_INTERVAL_SECS": "30",
                # Blind process states plus a hung recovery stop:
                # the stop helper is alive-but-unverifiable, so
                # signal-time settlement provably runs while the
                # interval wait is still live.
                "SOAK_STAT_READER": "false",
                "STUB_DOCKER_STOP_HANG": "1",
                # Short grace: blind settlement still runs, but the
                # run ends (~15 s) long before an orphaned 30 s wait
                # could self-exit (~35 s) — a lost wait is caught,
                # never outlived.
                "SOAK_CLEANUP_GRACE_SECS": "1",
            },
        )
        try:
            observed = self.wait_for_soak_checkpoint_record(timeout=30)
            # Same arrival-exact barrier as the sighted promptness
            # test (test-side /proc reads, unaffected by the
            # script's blind reader): the signal provably lands
            # while the specific 30 s wait sleeps.
            self.wait_for_soak_samples(1, timeout=10)
            pidfile = self.wait_for_work_file("sample-sleep.pid", timeout=15)
            stub_sleep = str(self.bin / "sleep")
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    announced = int(pidfile.read_text().strip())
                except (OSError, ValueError):
                    announced = None
                if announced is not None:
                    argv = self._cmdline_argv(announced)
                    if (
                        argv is not None
                        and len(argv) >= 2
                        and argv[-2] == stub_sleep
                        and argv[-1] == "30"
                        and self._stat_state(announced) == "S"
                    ):
                        break
                time.sleep(0.02)
            else:
                self.fail("interval sleep never reached its wait")
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            os.kill(proc.pid, signal.SIGTERM)
            # Fault injection, race-free: the recovery stop hangs
            # (its log arrival proves it spawned), so planting its
            # acknowledgement presents done-plus-alive to the blind
            # join — the settlement trigger — with an unbounded
            # plant window. Without independent settle tracking,
            # settlement steals the interval wait's ownership slot
            # and orphans it.
            stop_log = self.wait_for_work_file("recover-stop.log", timeout=15)
            stop_log.with_name("recover-stop.done").write_text("0\n")
            # The announced wait must die promptly (it is owned and
            # signaled): an orphaned 30 s wait survives ~28 s more,
            # and job-control exit-wait would mask it from the
            # session drain — so the death itself is observed here
            # (20 s bound, ~8 s minimum margin either way), and the
            # run's promptness is asserted below.
            signaled = time.monotonic()
            deadline = signaled + 20
            while time.monotonic() < deadline:
                if self._pid_dead(announced):
                    break
                time.sleep(0.02)
            else:
                self.fail("interval wait orphaned: still alive 20s after SIGTERM")
            try:
                # Blind settlement burns grace periods (recovery
                # helpers plus owned termination); the bound stays
                # generous but finite.
                output, _ = proc.communicate(timeout=120)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("soak run ignored SIGTERM under a blind reader")
            answered = time.monotonic() - signaled
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        # Prompt means the run reaped the wait, not waited it out
        # (a lost 30 s wait stalls the exit past 28 s).
        self.assertLess(answered, 20, "run waited out the orphaned interval wait")
        # Nothing survives in the session either.
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"interrupt leaked helpers: {survivors}")
        self.assertEqual(143, proc.returncode, output)
        summary = self.read_valid_soak_summary()
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        self.assertEqual("SIGTERM", summary["signal"])
        # Recovery ran through blind settlement and still carried
        # the checkpoint's outcomes.
        self.assertIsNotNone(summary["offered"])
        self.assertIsNotNone(summary["counts"])
        self.assertGreaterEqual(summary["offered"], observed["offered"])
        self.assertGreaterEqual(
            summary["counts"]["success"], observed["counts"]["success"]
        )
        self.assertEqual(
            observed["run_id"], summary["worker"]["result_run_id"]
        )
        # Blind honesty: killed-but-unverifiable helpers are
        # recorded, never claimed clean.
        self.assertNotEqual([], summary["unresolved_pids"])
        self.assert_valid_soak_summary(summary)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_interrupt_during_publish_keeps_terminal_record(self):
        """Q10 Box 1: SIGTERM at publication still leaves a record."""
        self.write_daemon_status()
        hold = self.container_tmp / "publish.hold"
        hold.write_text("hold\n")
        proc = self.popen_soak(
            extra_env={
                "STUB_SOAK_LEGACY_RESULT": "empty",
                "SOAK_PUBLISH_HOLD": str(hold),
            },
        )
        try:
            # Arrival: the controller acknowledged the pre-
            # publication hold itself (no fixed sleep over an
            # earlier event), so the signal provably lands in-hold.
            self.wait_for_container_file("publish.hold.ack")
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            os.kill(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("soak run ignored SIGTERM at publication")
        finally:
            try:
                hold.unlink()
            except OSError:
                pass
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"interrupt leaked helpers: {survivors}")
        self.assertEqual(143, proc.returncode, output)
        summary = self.read_valid_soak_summary()
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        self.assertEqual("SIGTERM", summary["signal"])
        self.assert_valid_soak_summary(summary)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_interrupt_during_removal_carries_outcomes(self):
        """Q10 Box 3: SIGTERM at removal keeps the validated counts."""
        self.write_daemon_status()
        hold = self.container_tmp / "removal.hold"
        hold.write_text("hold\n")
        proc = self.popen_soak(
            extra_env={
                "STUB_SOAK_LEGACY_RESULT": "empty",
                "SOAK_REMOVAL_HOLD": str(hold),
            },
        )
        try:
            # Arrival: the controller acknowledged the pre-removal
            # hold itself (no fixed sleep over an earlier event), so
            # the signal provably lands post-validation and in-hold,
            # and the validated counts must carry.
            self.wait_for_container_file("removal.hold.ack")
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            os.kill(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("soak run ignored SIGTERM at removal")
        finally:
            try:
                hold.unlink()
            except OSError:
                pass
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"interrupt leaked helpers: {survivors}")
        self.assertEqual(143, proc.returncode, output)
        summary = self.read_valid_soak_summary()
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        # The validated counts survived the interruption (nothing
        # re-nulled known evidence), including the compatibility
        # fields (the clean worker's outcomes, not nulls).
        self.assertGreater(summary["offered"], 0)
        self.assertGreater(summary["completed"], 0)
        self.assertTrue(summary["worker"]["complete"])
        self.assertGreater(summary["ok_signs"], 0)
        self.assertEqual(0, summary["fail_signs"])
        self.assert_valid_soak_summary(summary)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_interrupt_after_retirement_failure_recovers_checkpoint(self):
        """Q10 Box 3 (R4 finding 2): a stale result error never vetoes recovery."""
        self.write_daemon_status()
        hold = self.container_tmp / "removal.hold"
        hold.write_text("hold\n")
        proc = self.popen_soak(
            extra_env={
                "STUB_SOAK_LEGACY_RESULT": "empty",
                # Exactly the main-flow retirement fails; the
                # signal-time recovery stop succeeds.
                "STUB_DOCKER_STOP_FAIL_ONCE": "1",
                "SOAK_REMOVAL_HOLD": str(hold),
            },
        )
        try:
            # Arrival: the run reached pre-removal — the retirement
            # already failed (RESULT_ERROR latched), the copy was
            # skipped, validation no-opped. The worker finished
            # normally (DURATION=1); its terminal record sits in
            # the still-present container.
            self.wait_for_container_file("removal.hold.ack")
            self.assertIsNone(
                proc.poll(), "script exited before the interrupt was delivered"
            )
            os.kill(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
                self.fail("soak run ignored SIGTERM at removal")
        finally:
            try:
                hold.unlink()
            except OSError:
                pass
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        survivors = self._drain_session(proc.pid)
        self.assertEqual([], survivors, f"interrupt leaked helpers: {survivors}")
        self.assertEqual(143, proc.returncode, output)
        summary = self.read_valid_soak_summary()
        self.assertEqual("FAIL_INTERRUPTED", summary["verdict"])
        self.assertEqual("SIGTERM", summary["signal"])
        # The recovered record is the worker's terminal file,
        # exactly (the worker is dead — nothing advances past it).
        terminals = sorted(self.container_tmp.glob("soak_result-*.txt"))
        self.assertEqual(1, len(terminals))
        terminal = json.loads(terminals[0].read_text())
        self.assertTrue(terminal["complete"])
        self.assertTrue(summary["worker"]["complete"])
        self.assertEqual(terminal["run_id"], summary["worker"]["result_run_id"])
        self.assertEqual(terminal["offered"], summary["offered"])
        for key in ("success", "timeout", "error", "unknown", "unfinished"):
            self.assertEqual(terminal["counts"][key], summary["counts"][key])
        self.assertEqual(terminal["counts"]["success"], summary["ok_signs"])
        self.assertNotIn("partial checkpoint", " ".join(summary["reasons"]))
        self.assert_valid_soak_summary(summary)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_setup_hang_bounded(self):
        """Q10 Box 2: hung setup steps fail closed under a bound."""
        self.write_daemon_status()
        cases = {
            "provision-hang": {"STUB_SOAK_PROVISION_HANG": "1"},
            "create-hang": {"STUB_SOAK_RUN_HANG": "1"},
            "image-inspect-hang": {"STUB_IMAGE_INSPECT_HANG": "1"},
        }
        for name, extra in cases.items():
            with self.subTest(case=name):
                extra = dict(extra)
                extra["STUB_SOAK_LEGACY_RESULT"] = "empty"
                extra["SOAK_SETUP_TIMEOUT_SECS"] = "2"
                outcome = self.run_soak(extra_env=extra, bound=REJECT_BOUND_SECS)
                self.assert_completed(outcome, REJECT_BOUND_SECS)
                self.assertEqual(2, outcome.returncode, outcome.output)
                self.assertFalse((self.results_dir() / "soak.json").exists())
                if name == "image-inspect-hang":
                    # Refused before any creation was attempted.
                    self.assertEqual([], self.read_rm_manifest())
                    self.assertEqual([], self.read_soakworker_manifest())
                else:
                    # The worker existed when the step hung: the trap
                    # removed exactly the owned worker.
                    worker = self.read_soakworker_manifest()
                    self.assertGreaterEqual(len(worker), 1)
                    self.assertEqual(3, len(worker[0]))
                    self.assertEqual([worker[0][0]], self.read_rm_manifest())
                    reconcile = self.container_tmp / "inspect-manifest.log"
                    if name == "create-hang":
                        # Dispatched-but-unconfirmed: reconciled by its
                        # ownership label before removal.
                        self.assertIn(worker[0][0], reconcile.read_text())
                    else:
                        # Confirmed creation: removed directly, no
                        # reconcile needed.
                        self.assertFalse(reconcile.exists())
                self.assert_no_survivors(outcome)
                self.assertEqual([], self.work_dir_contents())

    def test_soak_sampling_clock_failure_publishes_terminal_summary(self):
        """Q10 Box 2: a clock failure mid-sampling still publishes JSON."""
        self.write_daemon_status()
        uptime = self.write_uptime_file()
        proc = self.popen_soak(
            extra_env={
                "STUB_SOAK_LEGACY_RESULT": "empty",
                "SOAK_UPTIME_PATH": str(uptime),
            },
        )
        try:
            # Barrier: the worker's acknowledgement file itself
            # exists (rows alone would not prove the subshell's
            # done-write), so the unlink lands mid-sampling with the
            # ack certain.
            self.wait_for_soak_ack_recorded()
            self.assertIsNone(
                proc.poll(), "script exited before the clock was failed"
            )
            uptime.unlink()
            survivors, output = self.drain_collect(proc)
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        self.assertEqual([], survivors, f"clock failure leaked helpers: {survivors}")
        summary = self.read_valid_soak_summary()
        # Cascade, pinned: the sampling latch fired and the finished
        # worker stayed acknowledged, but the result fetch and the
        # removal both fail closed without a measurable bound.
        self.assertEqual("FAIL_RESULT", summary["verdict"])
        self.assertNotEqual(0, proc.returncode, output)
        self.assertIn(
            "monotonic clock unreadable during soak sampling",
            " ".join(summary["reasons"]),
        )
        self.assertTrue(summary["worker"]["acked"])
        self.assertEqual(0, summary["worker"]["exit"])
        self.assert_valid_soak_summary(summary)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_join_clock_failure_settles_worker(self):
        """Q10 Box 2: a clock failure mid-join settles the worker at once."""
        self.write_daemon_status()
        uptime = self.write_uptime_file()
        proc = self.popen_soak(
            extra_env={
                "STUB_PKCS11_MODE": "hang",
                "STUB_SOAK_LEGACY_RESULT": "missing",
                "SOAK_UPTIME_PATH": str(uptime),
                "SOAK_WORKER_GRACE_SECS": "30",
                "SOAK_OP_TIMEOUT_SECS": "30",
            },
        )
        try:
            # Barrier: samples are flowing with the worker hung; the
            # unlink lands mid-sampling, and the dead clock then forces
            # the join's clock path too (grace never waited out).
            self.wait_for_soak_samples(3)
            self.assertIsNone(
                proc.poll(), "script exited before the clock was failed"
            )
            uptime.unlink()
            survivors, output = self.drain_collect(proc)
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        self.assertEqual([], survivors, f"clock failure leaked helpers: {survivors}")
        summary = self.read_valid_soak_summary()
        self.assertEqual("FAIL_WORKLOAD", summary["verdict"])
        self.assertNotEqual(0, proc.returncode, output)
        self.assertFalse(summary["worker"]["acked"])
        self.assertIn("unfinished", " ".join(summary["reasons"]))
        # Site proof: the join took its clock path (immediate
        # escalation), not the 30s grace wait.
        self.assertIn("monotonic clock unreadable during worker join", output)
        self.assert_valid_soak_summary(summary)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_blind_reader_fails_cleanup_closed(self):
        """Q10 Box 3: unreadable /proc fails cleanup closed, ack preserved."""
        self.write_daemon_status()
        outcome = self.run_soak(
            extra_env={
                "STUB_SOAK_LEGACY_RESULT": "empty",
                "SOAK_STAT_READER": "false",
            },
            bound=RUN_BOUND_SECS,
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        summary = self.read_valid_soak_summary()
        self.assertEqual("FAIL_CLEANUP", summary["verdict"])
        self.assertFalse(summary["cleanup_ok"])
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        self.assertNotEqual([], summary["unresolved_pids"])
        self.assertIn(
            "could not be verified", " ".join(summary["reasons"])
        )
        # Done-file evidence is /proc-independent: the acknowledgement
        # and the outcomes survive blindness.
        self.assertTrue(summary["worker"]["acked"])
        self.assertGreater(summary["completed"], 0)
        self.assert_valid_soak_summary(summary)
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_blind_hung_worker_settles_closed(self):
        """Q10 Box 2: blindness plus a hung worker still settles closed."""
        self.write_daemon_status()
        hold = self.container_tmp / "removal.hold"
        hold.write_text("hold\n")
        proc = self.popen_soak(
            extra_env={
                "STUB_SOAK_LEGACY_RESULT": "empty",
                "SOAK_STAT_READER": "false",
                "STUB_PKCS11_MODE": "hang",
                "SOAK_WORKER_GRACE_SECS": "2",
                "SOAK_OP_TIMEOUT_SECS": "30",
                "SOAK_CLEANUP_GRACE_SECS": "1",
                "SOAK_REMOVAL_HOLD": str(hold),
            },
        )
        try:
            # Arrival: the controller acknowledged the pre-removal
            # hold itself, so the join escalated long ago and removal
            # — which would reap the CLI in any case — is frozen.
            self.wait_for_container_file("removal.hold.ack")
            self.assertIsNone(
                proc.poll(), "script exited before the CLI was scanned"
            )
            # The M4 guarantee, observed mid-run: the escalation's
            # job-group signals killed the owned worker CLI even
            # though no /proc enumeration could see it. (The worker
            # itself is still hung — removal kills it later — so the
            # scan selects the CLI by its docker-exec command line,
            # never the worker shim.)
            cli = [
                pid
                for pid in session_members(proc.pid)
                if self._cmdline_contains(pid, "docker")
                and self._cmdline_contains(pid, "soak_worker.sh")
            ]
            self.assertEqual(
                [], cli, f"owned CLI survived blind escalation: {cli}"
            )
            hold.unlink()
            survivors, output = self.drain_collect(proc)
        finally:
            try:
                hold.unlink()
            except OSError:
                pass
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        self.assertEqual([], survivors, f"soak leaked helpers: {survivors}")
        summary = self.read_valid_soak_summary()
        # Unfinished work, unverifiable cleanup. Escalation is not
        # testimony: no ack.
        self.assertEqual("FAIL_WORKLOAD", summary["verdict"])
        self.assertNotEqual(0, proc.returncode, output)
        self.assertFalse(summary["worker"]["acked"])
        self.assertIsNone(summary["worker"]["exit"])
        self.assertIn("unfinished", " ".join(summary["reasons"]))
        self.assertIn(
            "could not be verified", " ".join(summary["reasons"])
        )
        self.assertFalse(summary["cleanup_ok"])
        self.assert_valid_soak_summary(summary)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_lost_acknowledgement_preserves_outcomes(self):
        """Q10 Box 2: a lost ack fails closed but preserves valid outcomes."""
        self.write_daemon_status()
        proc = self.popen_soak(
            extra_env={
                "DURATION": "2",
                "STUB_SOAK_LEGACY_RESULT": "empty",
                # Short grace/timeouts: a stopped subshell burns the
                # join grace, and a transient sample helper caught by
                # the sweep burns one sample timeout, both bounded.
                "SOAK_WORKER_GRACE_SECS": "2",
                "SOAK_SAMPLE_TIMEOUT_SECS": "2",
                "SOAK_CLEANUP_GRACE_SECS": "1",
            },
        )
        try:
            # Barrier: the worker runs (a 2s window, not a race); STOP
            # (not kill) the controller's worker-subshell child. A
            # killed subshell would let the join — and the result
            # fetch — race the still-running worker; a stopped one
            # holds the join in its grace while the worker finishes
            # underneath, so the ack is lost but the result is valid
            # at fetch time, deterministically. Selected by worker
            # identity (a descendant CLI serving the worker path) —
            # never by shape, and never the sampler's sleep.
            self.wait_for_soak_worker_spawn()
            self.assertIsNone(
                proc.poll(), "script exited before the ack was lost"
            )
            subshells = self._worker_subshell_pids(proc.pid)
            self.assertEqual(
                1, len(subshells), f"worker subshell not unique: {subshells}"
            )
            os.kill(subshells[0], signal.SIGSTOP)
            survivors, output = self.drain_collect(proc)
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        self.assertEqual([], survivors, f"soak leaked helpers: {survivors}")
        summary = self.read_valid_soak_summary()
        self.assertEqual("FAIL_WORKLOAD", summary["verdict"])
        self.assertNotEqual(0, proc.returncode, output)
        self.assertFalse(summary["worker"]["acked"])
        self.assertIsNone(summary["worker"]["exit"])
        self.assertIn("unfinished", " ".join(summary["reasons"]))
        # The valid, complete, run-matching result is self-validating:
        # its outcomes are published despite the lost ack.
        self.assertTrue(summary["worker"]["complete"])
        self.assertGreater(summary["offered"], 0)
        self.assertGreater(summary["completed"], 0)
        self.assert_valid_soak_summary(summary)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_partial_checkpoint_preserved_without_ack(self):
        """Q10 Box 3: a killed worker's checkpointed outcomes are published,
        exactly (per-op checkpoints bound the uncovered suffix to the
        in-flight write)."""
        self.write_daemon_status()
        proc = self.popen_soak(
            extra_env={
                "DURATION": "5",
                "STUB_SOAK_LEGACY_RESULT": "empty",
            },
        )
        try:
            # Barrier: a checkpoint with finished work exists (per-op
            # checkpoints land after every finished op); STOP the
            # worker itself (frozen — its checkpoint file cannot
            # advance), read the frozen record, then kill the subshell
            # (ack lost) and the worker (no terminal record ever
            # lands, so the fetch deterministically reads the frozen
            # partial checkpoint).
            self.wait_for_soak_checkpoint()
            self.assertIsNone(
                proc.poll(), "script exited before the ack was lost"
            )
            workers = [
                int(line[1])
                for line in self.read_soakworker_manifest()
                if len(line) == 2 and line[0] == "worker"
            ]
            self.assertEqual(1, len(workers))
            os.kill(workers[0], signal.SIGSTOP)
            frozen = None
            for path in self.container_tmp.glob("soak_result-*.txt"):
                try:
                    record = json.loads(path.read_text())
                except (OSError, ValueError):
                    continue
                if record.get("complete") is False:
                    frozen = record
            self.assertIsNotNone(frozen, "no frozen checkpoint to compare")
            self.assertFalse(frozen["complete"])
            self.assertGreater(frozen["offered"], 0)
            subshells = self._worker_subshell_pids(proc.pid)
            self.assertEqual(
                1, len(subshells), f"worker subshell not unique: {subshells}"
            )
            os.kill(subshells[0], signal.SIGKILL)
            os.kill(workers[0], signal.SIGKILL)
            _, output = self.drain_collect(proc)
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        # Test-owned wreckage (an in-flight op helper): stop it before
        # the leak oracle runs.
        self._kill_soak_orphans(proc.pid)
        survivors = session_members(proc.pid)
        self.assertEqual([], survivors, f"soak leaked helpers: {survivors}")
        summary = self.read_valid_soak_summary()
        self.assertEqual("FAIL_WORKLOAD", summary["verdict"])
        self.assertNotEqual(0, proc.returncode, output)
        self.assertFalse(summary["worker"]["acked"])
        self.assertFalse(summary["worker"]["complete"])
        self.assertIn("unfinished", " ".join(summary["reasons"]))
        # Exactness: the published outcomes equal the frozen worker
        # state, op for op — a killed worker loses nothing it
        # finished (beyond the in-flight atomic write the STOP may
        # have caught, which the frozen file already excludes).
        self.assertEqual(frozen["offered"], summary["offered"])
        for key in ("success", "timeout", "error", "unknown", "unfinished"):
            self.assertEqual(frozen["counts"][key], summary["counts"][key])
        self.assertEqual(
            frozen["busy_us"] * 1000, summary["busy_ns"]
        )
        self.assert_valid_soak_summary(summary)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_provision_failure_refuses_before_work(self):
        """Q10 Box 1: key provisioning that fails refuses before any work."""
        self.write_daemon_status()
        outcome = self.run_soak(
            extra_env={
                "STUB_SOAK_PROVISION_FAIL": "1",
                "STUB_SOAK_LEGACY_RESULT": "empty",
            },
            bound=REJECT_BOUND_SECS,
        )
        self.assert_completed(outcome, REJECT_BOUND_SECS)
        self.assertEqual(2, outcome.returncode, outcome.output)
        self.assertFalse((self.results_dir() / "soak.json").exists())
        # The worker existed when provisioning failed: the trap removed
        # exactly the owned worker.
        worker = self.read_soakworker_manifest()
        self.assertGreaterEqual(len(worker), 1)
        self.assertEqual(3, len(worker[0]))
        self.assertEqual([worker[0][0]], self.read_rm_manifest())
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_invalid_inputs_rejected(self):
        """Q10 Box 2: empty/invalid duration and rate inputs are refused."""
        self.write_daemon_status()
        cases = {
            "empty-duration": {"DURATION": ""},
            "zero-rps": {"RPS": "0"},
            "negative-duration": {"DURATION": "-5"},
            "alpha-rps": {"RPS": "fast"},
            "alpha-duration": {"DURATION": "long"},
        }
        for name, extra in cases.items():
            with self.subTest(case=name):
                extra = dict(extra)
                extra["STUB_SOAK_LEGACY_RESULT"] = "empty"
                outcome = self.run_soak(extra_env=extra, bound=REJECT_BOUND_SECS)
                self.assert_completed(outcome, REJECT_BOUND_SECS)
                self.assertEqual(2, outcome.returncode, outcome.output)
                self.assertFalse((self.results_dir() / "soak.json").exists())
                self.assert_no_survivors(outcome)
                self.assertEqual([], self.work_dir_contents())

    def test_soak_warmup_excluded_from_baseline(self):
        """Q10 Box 2: warmup samples never enter baseline/final windows."""
        self.write_daemon_status()
        proc = self.popen_soak(
            extra_env={
                "DURATION": "5",
                "STUB_SOAK_LEGACY_RESULT": "empty",
                "SOAK_WARMUP_SECS": "60",
                "SOAK_SAMPLE_INTERVAL_SECS": "1",
            },
        )
        try:
            # Barrier: one warmup row exists; drop RSS for the rest so
            # any warmup leak into the windows would show.
            self.wait_for_soak_samples(1)
            self.assertIsNone(
                proc.poll(), "script exited before RSS was lowered"
            )
            status = self.fake_proc / self.daemon_pid / "status"
            status.write_text("Name:\tdaemon\nVmRSS:\t 1024 kB\n")
            survivors, output = self.drain_collect(proc)
        finally:
            if proc.poll() is None:
                self._kill_session(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)
        self.assertEqual([], survivors, f"soak leaked helpers: {survivors}")
        summary = self.read_valid_soak_summary()
        self.assertEqual("FAIL_SAMPLER", summary["verdict"])
        self.assertNotEqual(0, proc.returncode, output)
        # Warmup (60s) covers the whole 5s run: every sample is
        # excluded, so no windows exist and growth is unevaluable.
        self.assertGreater(summary["samples"]["n_warmup_excluded"], 0)
        self.assertIsNone(summary["samples"]["baseline"]["rss_kb"])
        self.assert_valid_soak_summary(summary)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_records_limits_with_provenance(self):
        """Q10 Box 2: verdict limits are recorded inputs, not magic numbers."""
        self.write_daemon_status()
        outcome = self.run_soak(
            extra_env={
                "STUB_SOAK_LEGACY_RESULT": "empty",
                "SOAK_MAX_RSS_GROWTH_MB": "100",
                "SOAK_MAX_FD_GROWTH": "50",
            },
            bound=RUN_BOUND_SECS,
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        summary = self.read_valid_soak_summary()
        self.assertIsNotNone(summary.get("limits"), "limits not recorded")
        self.assertEqual(100, summary["limits"]["max_rss_growth_mb"])
        self.assertEqual(50, summary["limits"]["max_fd_growth"])
        self.assertEqual("explicit", summary["limits"]["provenance"])
        self.assertEqual("PASS", summary["verdict"])
        self.assertEqual(0, outcome.returncode, outcome.output)
        self.assert_valid_soak_summary(summary)
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_mixed_outcomes_preserved_with_rates(self):
        """Q10 Box 3: every operation outcome is preserved; offered,
        completed and busy-time rates are distinguished, not conflated."""
        self.write_daemon_status()
        outcome = self.run_soak(
            extra_env={
                # Two full pattern cycles with margin: each timeout
                # op costs its 1s op timeout inside the duration.
                "DURATION": "4",
                "STUB_SOAK_LEGACY_RESULT": "empty",
                "STUB_SOAK_OP_PATTERN": "ok,ok,timeout,error",
                "SOAK_OP_TIMEOUT_SECS": "1",
            },
            bound=RUN_BOUND_SECS,
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        summary = self.read_valid_soak_summary()
        self.assertEqual("FAIL_WORKLOAD", summary["verdict"])
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        counts = summary["counts"]
        self.assertGreater(counts["success"], 0)
        self.assertGreater(counts["timeout"], 0)
        self.assertGreater(counts["error"], 0)
        # Conservation: offered splits exactly into outcomes.
        self.assertEqual(
            summary["offered"],
            counts["success"]
            + counts["timeout"]
            + counts["error"]
            + counts["unknown"]
            + counts["unfinished"],
        )
        self.assertEqual(counts["total"], summary["offered"])
        self.assertEqual(
            summary["completed"],
            counts["success"] + counts["timeout"] + counts["error"],
        )
        # Rate definitions pinned from the reported fields (never
        # presented as one another's value). Wall rates use the
        # worker's measured elapsed (the matched population
        # interval), not the controller's sampling window.
        elapsed = summary["worker"]["elapsed_s"]
        self.assertGreater(elapsed, 0)
        self.assertAlmostEqual(
            summary["completed_per_wall_s"],
            summary["completed"] / elapsed,
        )
        self.assertAlmostEqual(
            summary["ok_per_wall_s"],
            counts["success"] / elapsed,
        )
        # Busy time aggregates every finished op, so the busy rate is
        # completed-per-busy-second (compare.py's success-only
        # per_busy_second would need per-outcome timing the worker does
        # not record; the name differs deliberately).
        self.assertAlmostEqual(
            summary["completed_per_busy_s"],
            summary["completed"] / (summary["busy_ns"] / 1e9),
        )
        self.assert_valid_soak_summary(summary)
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_comma_locale_rates_stay_valid_json(self):
        """Q10 Box 3: a comma-decimal locale cannot break summary JSON."""
        self.write_daemon_status()
        outcome = self.run_soak(
            extra_env={
                "DURATION": "2",
                "STUB_SOAK_LEGACY_RESULT": "empty",
                "LC_ALL": "en_DK.utf8",
            },
            bound=RUN_BOUND_SECS,
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        # Valid JSON with numeric (never comma-formatted) rates.
        summary = self.read_valid_soak_summary()
        self.assertEqual("PASS", summary["verdict"])
        self.assertEqual(0, outcome.returncode, outcome.output)
        for key in (
            "completed_per_wall_s",
            "ok_per_wall_s",
            "completed_per_busy_s",
        ):
            self.assertIsInstance(summary[key], float)
        self.assert_valid_soak_summary(summary)
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_worker_result_schema_rejects_defects(self):
        """Q10 Box 3: the worker-result schema validates failure records."""
        self.write_daemon_status()
        cases = ["bad-sum", "missing-keys", "negative", "bad-types", "huge"]
        for mode in cases:
            with self.subTest(mode=mode):
                outcome = self.run_soak(
                    extra_env={
                        "STUB_SOAK_LEGACY_RESULT": "empty",
                        "STUB_SOAK_RESULT_MODE": mode,
                    },
                    bound=RUN_BOUND_SECS,
                )
                self.assert_completed(outcome, RUN_BOUND_SECS)
                self.assertNotEqual(0, outcome.returncode, outcome.output)
                summary = self.read_valid_soak_summary()
                self.assertEqual("FAIL_RESULT", summary["verdict"])
                self.assertIn("result", " ".join(summary["reasons"]))
                # Unrepresentable counts must not wrap into outcomes.
                self.assertIsNone(summary["offered"])
                self.assertIsNone(summary["counts"])
                self.assert_valid_soak_summary(summary)
                self.assert_no_survivors(outcome)
                self.assertEqual([], self.work_dir_contents())

    def test_soak_hostile_result_id_injects_nothing(self):
        """Q10 Box 3: a hostile foreign id injects no counts, breaks no JSON."""
        self.write_daemon_status()
        outcome = self.run_soak(
            extra_env={
                "STUB_SOAK_LEGACY_RESULT": "empty",
                "STUB_SOAK_RESULT_MODE": "hostile-id",
            },
            bound=RUN_BOUND_SECS,
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertNotEqual(0, outcome.returncode, outcome.output)
        summary = self.read_valid_soak_summary()
        self.assertEqual("FAIL_RESULT", summary["verdict"])
        # The embedded fake record stayed inert: no counts published.
        self.assertIsNone(summary["offered"])
        self.assertIsNone(summary["counts"])
        # The observed id round-trips through complete JSON encoding.
        self.assertEqual(
            "x\nsuccess=7\noffered=7\t\x01tail",
            summary["worker"]["result_run_id"],
        )
        self.assert_valid_soak_summary(summary)
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())

    def test_soak_clean_run_passes_with_compare_receipt(self):
        """Q10 Boxes 3-4: a clean run passes with a compare-compatible receipt."""
        self.write_daemon_status()
        outcome = self.run_soak(
            # Two seconds of load: a whole-second worker window with
            # margin against setup-speed skew (never a zero-op run).
            extra_env={"STUB_SOAK_LEGACY_RESULT": "empty", "DURATION": "2"},
            bound=RUN_BOUND_SECS,
        )
        self.assert_completed(outcome, RUN_BOUND_SECS)
        self.assertEqual(0, outcome.returncode, outcome.output)
        summary = self.read_valid_soak_summary()
        self.assertEqual("PASS", summary["verdict"])
        self.assert_valid_soak_summary(summary)
        self.assertEqual([], summary["reasons"])
        self.assertTrue(summary["cleanup_ok"])
        # compare.py reuse, executed: the soak manifest conforms to the
        # receipt identity constants (drift here breaks loudly). The
        # counts shape is pinned against _count_outcomes itself —
        # deliberate white-box coupling, not a duplicated literal.
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "perf_compare", str(ROOT / "scripts" / "perf" / "compare.py")
        )
        perf_compare = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(perf_compare)
        manifest = summary["identities"]
        self.assertEqual(
            set(manifest["provider"]),
            set(perf_compare.PROVIDER_IDENTITY_KEYS),
        )
        self.assertEqual(
            set(manifest["workload"]),
            set(perf_compare.WORKLOAD_IDENTITY_KEYS),
        )
        self.assertEqual(
            set(summary["counts"]),
            set(perf_compare._count_outcomes([])),
        )
        self.assertLessEqual(
            set(summary["counts"]) - {"censored", "total", "unfinished"},
            set(perf_compare.FINISHED_OUTCOMES),
        )
        # The owned worker container cycled exactly once.
        worker = self.read_soakworker_manifest()
        self.assertGreaterEqual(len(worker), 1)
        self.assertEqual(3, len(worker[0]))
        self.assertEqual([worker[0][0]], self.read_rm_manifest())
        self.assertEqual(worker[0][0], summary["run_id"])
        self.assert_no_survivors(outcome)
        self.assertEqual([], self.work_dir_contents())


if __name__ == "__main__":
    unittest.main()

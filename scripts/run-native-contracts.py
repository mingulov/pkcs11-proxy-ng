#!/usr/bin/env python3
"""Strict, standalone native-contract feedback gate (Linux; no provider qualification)."""
import argparse
import ctypes
import hashlib
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


class GateError(RuntimeError):
    pass


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def owned_children():
    """Only direct children of this single-threaded runner, never host-wide PIDs."""
    path = Path(f'/proc/{os.getpid()}/task/{os.getpid()}/children')
    return [int(pid) for pid in path.read_text().split()]


def prepare_child_ownership():
    # Orphaned descendants, including double-fork/setsid daemons, reparent to
    # this runner. No other processes are spawned concurrently by the runner.
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        raise GateError('Linux pidfd ownership is mandatory')
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise GateError(f'cannot establish Linux child subreaper: errno={ctypes.get_errno()}')
    enabled = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(enabled), 0, 0, 0) != 0 or enabled.value != 1:
        raise GateError('cannot verify Linux child subreaper')
    # Probe pidfd access before launching anything we would need to settle.
    fd = os.pidfd_open(os.getpid())
    try:
        signal.pidfd_send_signal(fd, 0)
    finally:
        os.close(fd)
    if owned_children():
        raise GateError('pre-existing runner children prevent exclusive ownership')


def kill_owned_pid(pid):
    # Opening a pidfd for a direct, unreaped child prevents PID-reuse races.
    # Descendants cannot be reused while still our unreaped children.
    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        return
    try:
        signal.pidfd_send_signal(fd, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        os.close(fd)


def settle_owned_children(process):
    """Kill/reap the known root, then all adopted descendants, including setsid."""
    root_running = process.poll() is None
    if root_running:
        kill_owned_pid(process.pid)
    process.wait(timeout=5)
    descendants = owned_children()
    observed = set(descendants)
    reaped = []
    deadline = time.monotonic() + 5
    while descendants:
        if time.monotonic() >= deadline:
            raise GateError('owned descendants did not settle before cleanup deadline')
        for pid in descendants:
            kill_owned_pid(pid)
        # Killing an adopted parent can adopt additional grandchildren. Reap
        # all current children, then rescan until there is no owned subtree.
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if not pid:
                break
            reaped.append(pid)
            observed.add(pid)
        descendants = owned_children()
        observed.update(descendants)
        if descendants:
            time.sleep(0.01)
    return root_running, sorted(observed), reaped


def run_child(argv, cwd, env, timeout, commands):
    """File-backed output plus exclusive Linux subtree ownership, including detachment."""
    started = time.monotonic()
    entry = {'argv': [str(x) for x in argv], 'status': 'running', 'cleanup_complete': False,
             'ownership': 'linux-subreaper-pidfd'}
    commands.append(entry)
    prepare_child_ownership()
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        entry['pid'] = process.pid
        timed_out = False
        try:
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
        finally:
            # Runs on normal exits, timeouts and exceptions. Orphans from any
            # descendant session are our children and must all be reaped.
            root_killed, descendants, reaped = settle_owned_children(process)
            entry.update(cleanup_complete=True, reaped=True, root_killed=root_killed,
                         owned_descendants=descendants, reaped_descendants=reaped)
        output.seek(0)
        text = output.read().decode('utf-8', errors='replace')
    entry.update(returncode=process.returncode, duration_seconds=time.monotonic() - started,
                 status='timeout' if timed_out else 'exited', output=text)
    if timed_out or descendants or process.returncode:
        raise GateError(f"child failed (timeout={timed_out}, descendants={descendants}, "
                        f"exit={process.returncode}): {argv}\n{text[-4000:]}")
    return text


def observed_native_evidence(output, expected):
    if not expected:
        return None
    records = [line for line in output.splitlines() if 'shape-evidence ' in line]
    if len(records) != 1:
        raise GateError('native observation requires exactly one shape-evidence record')
    record = records[0]
    label = re.search(r'\bshape-evidence ([a-z-]+):', record)
    if label is None or label.group(1) != expected['control']:
        raise GateError('native observation control identity mismatch')
    observed = {'control': label.group(1)}
    for key in ('backend_admissions', 'native_entries'):
        if len(re.findall(r'\b' + key + '=', record)) != 1:
            raise GateError(f'missing/duplicate native observation field: {key}')
        match = re.search(r'\b' + key + r'=([0-9]+)(?=\s|$)', record)
        if match is None or len(match.group(1)) > 20:
            raise GateError(f'malformed native observation field: {key}')
        observed[key] = int(match.group(1))
        if observed[key] > (1 << 64) - 1 or observed[key] != expected[key]:
            raise GateError(f'wrong native observation: {observed}')
    return observed


def load_manifest(root):
    path = root / 'tests/native-contracts.json'
    manifest = json.loads(path.read_text())
    if manifest.get('schema') != 'native-contract-manifest/v1':
        raise GateError('unsupported manifest schema')
    cases = [case for lane in manifest['lanes'] for case in lane['cases']]
    ids = [case['id'] for case in cases]
    if not ids or len(ids) != len(set(ids)):
        raise GateError('manifest requires nonempty unique exact case IDs')
    if any(not case.get('markers') for case in cases):
        raise GateError('each selected case requires semantic completion markers')
    return manifest, ids


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--list', action='store_true', help='list only; never a passing gate')
    modes.add_argument('--no-run', action='store_true', help='build/validate inventory only; never pass')
    parser.add_argument('--timeout', type=float, default=45, help='per-case timeout in seconds')
    args = parser.parse_args(argv)
    os.umask(0o077)
    gate_started = time.monotonic()
    temporary_paths = []
    root = Path(__file__).resolve().parents[1]
    receipt = {'schema': 'native-contract/v1', 'status': 'failed', 'selected_ids': [],
               'executed_ids': [], 'cases': [], 'commands': [], 'artifacts': {},
               'cleanup': {'complete': False}}
    exit_code = 1
    completed_status = None
    try:
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise GateError('timeout must be finite and positive')
        manifest, ids = load_manifest(root)
        receipt.update(selected_ids=ids, excluded=manifest['excluded'],
                       manifest_sha256=digest(root / 'tests/native-contracts.json'))
        sources = sorted({p for pattern in manifest['sources'] for p in root.glob(pattern)
                          if p.is_file()})
        if not sources:
            raise GateError('source identity inventory is empty')
        receipt['sources'] = {str(p.relative_to(root)): digest(p) for p in sources}
        if args.list:
            completed_status = 'listed-not-executed'
            print('\n'.join(ids))
        else:
            if sys.platform != 'linux':
                raise GateError('compact gate requires Linux subreaper/pidfd ownership and native libraries')
            cargo = shutil.which('cargo')
            flock = shutil.which('flock')
            if not cargo or not flock:
                raise GateError('mandatory cargo/flock tool missing')
            # Remove all inherited fixture and proxy selectors, including child-entry
            # dispatch variables. Only this invocation's declared artifacts are admitted.
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith(('PKCS11_PROXY_', 'RETAINED_ORACLE_', 'EXACT_ORACLE_'))}
            env.update(CARGO_TARGET_DIR=str(root / 'target'),
                       CARGO_BUILD_BUILD_DIR=str(root / 'target/build'), CARGO_BUILD_JOBS='2')
            with tempfile.TemporaryDirectory(prefix='pkcs11-native-contract-') as tmp:
                temporary_paths.append(Path(tmp))
                os.chmod(tmp, 0o700)
                env['TMPDIR'] = tmp
                artifacts = {}
                for build in manifest['builds']:
                    output = run_child([flock, '/tmp/pkcs11-proxy-testing-feedback-cargo.lock',
                                        cargo, *build['args'], '--message-format=json'],
                                       root, env, 1800, receipt['commands'])
                    messages = []
                    for line in output.splitlines():
                        if line.startswith('{'):
                            messages.append(json.loads(line))
                    for spec in build['artifacts']:
                        matches = [m for m in messages if m.get('reason') == 'compiler-artifact'
                                   and m['target']['name'] == spec['target']
                                   and spec['kind'] in m['target']['kind']]
                        candidates = {str(m['executable']) for m in matches if m.get('executable')} \
                            if spec.get('executable') else \
                            {f for m in matches for f in m['filenames'] if f.endswith('.so')}
                        if len(candidates) != 1:
                            raise GateError(f"missing/ambiguous built artifact: {spec['id']}")
                        path = Path(candidates.pop()).resolve()
                        if not path.is_file():
                            raise GateError(f'missing built artifact: {path}')
                        artifacts[spec['id']] = path
                        receipt['artifacts'][spec['id']] = {'path': str(path), 'sha256': digest(path)}
                for key, artifact in manifest['environment'].items():
                    env[key] = str(artifacts[artifact])
                # Validate all lanes before executing any case. Full exact inventories
                # catch new/renamed ignored cases instead of silently narrowing coverage.
                for lane in manifest['lanes']:
                    binary = artifacts[lane['artifact']]
                    flags = ['--ignored'] if lane.get('ignored') else []
                    listing = run_child([str(binary), '--list', '--format', 'terse', *flags],
                                        root, env, args.timeout, receipt['commands'])
                    listed = re.findall(r'^(.+): test$', listing, re.MULTILINE)
                    prefix = lane.get('prefix', '')
                    selected = [name for name in listed if name.startswith(prefix)]
                    expected = [case['id'] for case in lane['cases']]
                    if not selected or len(selected) != len(set(selected)) or set(selected) != set(expected):
                        raise GateError(f'inventory mismatch: expected={expected}, actual={selected}')
                if args.no_run:
                    completed_status = 'built-not-executed'
                else:
                    for lane in manifest['lanes']:
                        for case in lane['cases']:
                            started = time.monotonic()
                            result = {'id': case['id'], 'status': 'failed'}
                            receipt['cases'].append(result)
                            command_index = len(receipt['commands'])
                            try:
                                output = run_child([str(artifacts[lane['artifact']]), '--exact', case['id'],
                                                    '--ignored', '--test-threads=1', '--nocapture'],
                                                   root, env, args.timeout, receipt['commands'])
                                # Require harness terminal accounting AND post-assertion evidence.
                                if (len(re.findall(r'test result:', output)) != 1
                                        or not re.search(r'test result: ok\. 1 passed; 0 failed; 0 ignored;', output)):
                                    raise GateError(f"zero/malformed terminal work: {case['id']}")
                                if any(len(re.findall(r'(?m)(?<!\S)' + re.escape(marker) + r'$', output)) != 1 for marker in case['markers']):
                                    raise GateError(f"missing/duplicate semantic marker: {case['id']}")
                                observed = observed_native_evidence(output, case.get('evidence'))
                                result.update(status='passed', markers=case['markers'],
                                              native_evidence=observed,
                                              duration_seconds=time.monotonic() - started)

                            finally:
                                result['duration_seconds'] = time.monotonic() - started
                                commands = receipt['commands'][command_index:]
                                if commands and commands[0].get('pid'):
                                    receipt['executed_ids'].append(case['id'])
                    if receipt['executed_ids'] != ids:
                        raise GateError('executed IDs do not equal the manifest')
                    if receipt['sources'] != {str(p.relative_to(root)): digest(p) for p in sources}:
                        raise GateError('source files changed during the gate')
                    if any(digest(Path(a['path'])) != a['sha256'] for a in receipt['artifacts'].values()):
                        raise GateError('built artifacts changed during the gate')
                    completed_status = 'passed'
        receipt['cleanup']['complete'] = (not any(p.exists() for p in temporary_paths)
                                            and all(c.get('cleanup_complete', False) for c in receipt['commands']))
        if not receipt['cleanup']['complete']:
            raise GateError('required cleanup is incomplete')
        receipt['status'] = completed_status
        exit_code = 0
    except BaseException as error:
        receipt['status'] = 'failed'
        exit_code = 1
        receipt['error'] = str(error)
        # A failed settlement or failed directory removal remains explicitly
        # incomplete. No exception inherits a prior successful status or exit.
        receipt['cleanup']['complete'] = (not any(p.exists() for p in temporary_paths)
                                            and all(c.get('cleanup_complete', False) for c in receipt['commands']))
        print(f'native-contract failed: {error}', file=sys.stderr)
    receipt['duration_seconds'] = time.monotonic() - gate_started
    args.output.parent.mkdir(parents=True, exist_ok=True)
    staging = args.output.with_name(args.output.name + f'.{os.getpid()}.tmp')
    staging.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    staging.replace(args.output)
    print(f"native-contract: {receipt['status']} ({len(receipt['executed_ids'])}/{len(receipt['selected_ids'])})")
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())

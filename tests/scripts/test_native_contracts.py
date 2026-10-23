"""Behavioral controls for the compact runner; native binaries are hermetic children."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/run-native-contracts.py'


class NativeContractsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'scripts').mkdir()
        (self.root / 'tests').mkdir()
        self.output = self.root / 'receipt.json'

    def run_gate(self, mode='ok', extra=(), polluted=False, timeout='0.3'):
        self.assertTrue(SCRIPT.is_file(), 'native contract runner must exist')
        shutil.copy2(SCRIPT, self.root / 'scripts/run-native-contracts.py')
        manifest = {'schema': 'native-contract-manifest/v1', 'builds': [
            {'id': 'fixture', 'args': ['test', '--locked', '--no-run'],
             'artifacts': [{'id': 'test-bin', 'target': 'fixture', 'kind': 'test', 'executable': True}]}],
            'sources': ['source.rs'], 'environment': {}, 'excluded': ['real providers'],
            'lanes': [{'artifact': 'test-bin', 'ignored': True,
                       'cases': [{'id': 'native_case', 'markers': ['native-contract-complete:native_case'], 'evidence': {'control': 'native-entry', 'backend_admissions': 1, 'native_entries': 1}}]}]}
        if mode == 'empty_manifest':
            manifest['lanes'][0]['cases'] = []
        (self.root / 'source.rs').write_text('// fixture source\n')
        (self.root / 'tests/native-contracts.json').write_text(json.dumps(manifest))
        binary = self.root / 'native-child'
        binary.write_text('''#!/usr/bin/env python3
import os, sys, time
mode = os.environ['FIXTURE_MODE']
if '--list' in sys.argv:
    if mode == 'empty': pass
    elif mode == 'renamed': print('renamed_case: test')
    else: print('native_case: test')
    if mode == 'extra_inventory': print('extra_case: test')
    sys.exit(0)
if mode in ('timeout', 'detached', 'detached_timeout'):
    import subprocess
    p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)', os.environ['CHILD_PID']], start_new_session=mode != 'timeout')
    open(os.environ['CHILD_PID'], 'w').write(str(p.pid))
    if mode != 'detached': time.sleep(60)
if any(k.startswith('PKCS11_PROXY_') for k in os.environ): sys.exit(42)
if mode != 'early': print('test native_case ... native-contract-complete:native_case')
if mode == 'duplicate_marker': print('native-contract-complete:native_case')
record = 'shape-evidence native-entry: provider=fixture backend_admissions=1 native_entries=' + ('0' if mode == 'wrong_evidence' else '10' if mode == 'ten_entries' else '1')
print(record)
if mode == 'duplicate_evidence': print(record)
if mode == 'conflicting_evidence': print('shape-evidence native-entry: provider=fixture backend_admissions=1 native_entries=0')
print('test native_case ... ok')
print('test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out' if mode == 'zero' else 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out')
if mode == 'extra_terminal': print('test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out')
sys.exit(7 if mode == 'fail' else 0)
''')
        binary.chmod(0o755)
        cargo = self.root / 'cargo'
        cargo.write_text('''#!/usr/bin/env python3
import json, os
from pathlib import Path
p = Path(__file__).parent / 'native-child'
print(json.dumps({'reason':'compiler-artifact','target':{'name':'fixture','kind':['test']},'executable':str(p),'filenames':[str(p)]}))
if os.environ['FIXTURE_MODE'] == 'missing': p.unlink()
''')
        cargo.chmod(0o755)
        flock = self.root / 'flock'
        flock.write_text('#!/usr/bin/env python3\nimport os, sys\nos.execvp(sys.argv[2], sys.argv[2:])\n')
        flock.chmod(0o755)
        env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ['PATH'],
                   FIXTURE_MODE=mode, CHILD_PID=str(self.root / 'child.pid'))
        if mode == 'tool':
            cargo.unlink()
            env['PATH'] = str(self.root)
        if polluted:
            env['PKCS11_PROXY_NATIVE_STOP_CHILD'] = 'hostile-selector'
            env['PKCS11_PROXY_ENDPOINT'] = 'http://external.invalid'
        launcher = self.root / 'scripts/run-native-contracts.py'
        if mode == 'cleanup_failure':
            launcher = self.root / 'inject-cleanup-failure.py'
            launcher.write_text("import runpy, tempfile\n"
                                "original = tempfile.TemporaryDirectory.cleanup\n"
                                "def fail(self):\n"
                                "    if 'pkcs11-native-contract-' in self.name: raise OSError('induced removal failure')\n"
                                "    original(self)\n"
                                "tempfile.TemporaryDirectory.cleanup = fail\n"
                                "runpy.run_path(" + repr(str(self.root / 'scripts/run-native-contracts.py')) + ", run_name='__main__')\n")
        timeout_args = [] if timeout is None else ['--timeout', timeout]
        return subprocess.run([sys.executable, str(launcher),
                               '--output', str(self.output), *timeout_args, *extra],
                              env=env, capture_output=True, text=True, timeout=8)

    def test_success_receipt_and_polluted_environment(self):
        p = self.run_gate(polluted=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        receipt = json.loads(self.output.read_text())
        self.assertEqual(receipt['schema'], 'native-contract/v1')
        self.assertEqual(receipt['status'], 'passed')
        self.assertEqual(receipt['selected_ids'], ['native_case'])
        self.assertEqual(receipt['executed_ids'], ['native_case'])
        self.assertTrue(receipt['cleanup']['complete'])
        self.assertIn('sha256', receipt['artifacts']['test-bin'])
        self.assertEqual(receipt['cases'][0]['native_evidence'],
                         {'control': 'native-entry', 'backend_admissions': 1, 'native_entries': 1})

    def test_invalid_timeout_refuses_before_any_child_launch(self):
        for timeout in ('nan', 'inf', '-inf', '0', '-0.1'):
            with self.subTest(timeout=timeout):
                p = self.run_gate(extra=[f'--timeout={timeout}'])
                self.assertNotEqual(p.returncode, 0, p.stdout)
                receipt = json.loads(self.output.read_text())
                self.assertEqual(receipt['status'], 'failed')
                self.assertEqual(receipt['commands'], [])
                self.assertEqual(receipt['executed_ids'], [])
                self.assertIn('timeout', receipt['error'])
                self.assertIn('native-contract failed:', p.stderr)
                self.assertTrue(receipt['cleanup']['complete'])

    def test_default_timeout_executes_selected_case(self):
        p = self.run_gate(timeout=None)
        self.assertEqual(p.returncode, 0, p.stderr)
        receipt = json.loads(self.output.read_text())
        self.assertEqual(receipt['status'], 'passed')
        self.assertEqual(receipt['executed_ids'], ['native_case'])

    def test_fail_closed_controls(self):
        for mode in ('tool', 'missing', 'empty', 'empty_manifest', 'renamed', 'early', 'fail', 'zero',
                     'extra_inventory', 'duplicate_marker', 'wrong_evidence', 'extra_terminal'):
            with self.subTest(mode=mode):
                p = self.run_gate(mode)
                self.assertNotEqual(p.returncode, 0, p.stdout)
                self.assertEqual(json.loads(self.output.read_text())['status'], 'failed')

    def test_missing_native_observation_fails(self):
        p = self.run_gate('wrong_evidence')
        self.assertNotEqual(p.returncode, 0)

    def test_timeout_kills_process_group(self):
        p = self.run_gate('timeout')
        self.assertNotEqual(p.returncode, 0)
        receipt = json.loads(self.output.read_text())
        self.assertEqual(receipt['status'], 'failed')
        self.assertTrue(receipt['cleanup']['complete'])
        pid = int((self.root / 'child.pid').read_text())
        status = Path(f'/proc/{pid}/stat')
        self.assertFalse(status.exists(), 'owned timeout descendant must be reaped')

    def test_removal_failure_after_semantic_pass_rejects_success(self):
        p = self.run_gate('cleanup_failure')
        receipt = json.loads(self.output.read_text())
        self.assertEqual(receipt['cases'][0]['status'], 'passed')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(receipt['status'], 'failed')
        self.assertFalse(receipt['cleanup']['complete'])

    def test_exact_unique_native_observations(self):
        for mode in ('ten_entries', 'duplicate_evidence', 'conflicting_evidence'):
            with self.subTest(mode=mode):
                p = self.run_gate(mode)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(json.loads(self.output.read_text())['status'], 'failed')

    def test_detached_descendant_is_killed_and_reaped(self):
        for mode in ('detached', 'detached_timeout'):
            with self.subTest(mode=mode):
                p = self.run_gate(mode)
                pid = int((self.root / 'child.pid').read_text())
                try:
                    self.assertNotEqual(p.returncode, 0)
                    self.assertFalse(Path(f'/proc/{pid}').exists(), 'owned detached child must be reaped')
                    self.assertTrue(json.loads(self.output.read_text())['cleanup']['complete'])
                finally:
                    cmdline = Path(f'/proc/{pid}/cmdline')
                    if cmdline.exists() and str(self.root / 'child.pid').encode() in cmdline.read_bytes():
                        try:
                            os.kill(pid, 9)
                        except ProcessLookupError:
                            pass

    def test_information_modes_cannot_claim_pass(self):
        for mode in ('--list', '--no-run'):
            with self.subTest(mode=mode):
                p = self.run_gate(extra=[mode])
                self.assertEqual(p.returncode, 0, p.stderr)
                receipt = json.loads(self.output.read_text())
                self.assertNotEqual(receipt['status'], 'passed')
                self.assertEqual(receipt['executed_ids'], [])


if __name__ == '__main__':
    unittest.main()

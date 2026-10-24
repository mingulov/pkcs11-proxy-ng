"""Required feedback scheduling and fail-closed script-runner contracts."""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/run-script-tests.py"


def workflow(name="ci"):
    return yaml.safe_load((ROOT / f".github/workflows/{name}.yml").read_text())


class ScriptRunnerTests(unittest.TestCase):
    def run_fixture(self, body=None, *, path=None, no_site=False, yaml_version=None,
                    modules=None, args=(), timings=False, receipt_directory=False,
                    stale_receipt=False):
        # Exercise the real entrypoint in an independent repository inventory.
        with tempfile.TemporaryDirectory(prefix="script-gate-") as temp:
            root = Path(temp)
            (root / "scripts").mkdir()
            (root / "tests/scripts").mkdir(parents=True)
            self.assertTrue(RUNNER.is_file(), "required script runner is absent")
            shutil.copyfile(RUNNER, root / "scripts/run-script-tests.py")
            shutil.copyfile(ROOT / "requirements-script-tests.txt",
                            root / "requirements-script-tests.txt")
            if yaml_version is not None:
                (root / "scripts/yaml.py").write_text(f"__version__ = {yaml_version!r}\n")
            fixtures = dict(modules or {})
            if body is not None:
                fixtures["test_fixture.py"] = body
            for name, source in fixtures.items():
                fixture = root / "tests/scripts" / name
                fixture.parent.mkdir(parents=True, exist_ok=True)
                fixture.write_text(source)
            env = dict(os.environ)
            env.pop("PYTHONPATH", None)
            if path is not None:
                env["PATH"] = path
            command = [sys.executable]
            if no_site:
                command.append("-S")
            command.append(str(root / "scripts/run-script-tests.py"))
            receipt = root / "timings.json"
            if stale_receipt:
                receipt.write_text(json.dumps({"status": "passed", "old": True}))
            if timings:
                if receipt_directory:
                    receipt.mkdir()
                command.extend(["--timings-json", str(receipt)])
            command.extend(args)
            result = subprocess.run(command, cwd=root, env=env, text=True,
                                    capture_output=True, timeout=30)
            result.timings = json.loads(receipt.read_text()) if receipt.is_file() else None
            result.markers = {path.name: path.read_text() for path in root.glob("*.marker")}
            return result

    def test_pass_runs_discovered_suite(self):
        result = self.run_fixture("import unittest\nclass Gate(unittest.TestCase):\n"
                                  " def test_pass(self): self.assertEqual(2+2, 4)\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Ran 1 test", result.stderr)

    def test_failure_cannot_pass_gate(self):
        result = self.run_fixture("import unittest\nclass Gate(unittest.TestCase):\n"
                                  " def test_fail(self): self.fail('fixture failure')\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fixture failure", result.stderr)

    def test_unexpected_skip_cannot_pass_gate(self):
        result = self.run_fixture("import unittest\nclass Gate(unittest.TestCase):\n"
                                  " def test_skip(self): self.skipTest('fixture skip')\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected skip", result.stderr.lower())

    def test_empty_collection_cannot_pass_gate(self):
        result = self.run_fixture(None)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("zero tests", result.stderr.lower())

    def test_import_error_cannot_pass_gate(self):
        result = self.run_fixture("raise RuntimeError('fixture import error')\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fixture import error", result.stderr)

    def test_missing_dependency_is_preflight_failure(self):
        result = self.run_fixture("raise RuntimeError('must not collect')\n", no_site=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PyYAML", result.stderr)
        self.assertNotIn("must not collect", result.stderr)

    def test_missing_tools_are_preflight_failure(self):
        result = self.run_fixture("raise RuntimeError('must not collect')\n", path="")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing required tools", result.stderr.lower())
        self.assertNotIn("must not collect", result.stderr)

    def test_wrong_dependency_version_is_preflight_failure(self):
        result = self.run_fixture("raise RuntimeError('must not collect')\n",
                                  yaml_version="0.0.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("found 0.0.0", result.stderr)
        self.assertNotIn("must not collect", result.stderr)

    def test_default_receipt_records_complete_inventory_and_distinct_clocks(self):
        alpha = ("import time, unittest\ntime.sleep(0.02)\n"
                 "class Gate(unittest.TestCase):\n"
                 " @classmethod\n def setUpClass(cls): time.sleep(0.02)\n"
                 " def test_alpha(self): time.sleep(0.02)\n")
        beta = "import unittest\nclass Gate(unittest.TestCase):\n def test_beta(self): pass\n"
        result = self.run_fixture(modules={"test_alpha.py": alpha, "test_beta.py": beta},
                                  timings=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = result.timings
        self.assertIsNotNone(report, "requested timing receipt is absent")
        self.assertEqual(report["format"], "script-regressions/v1")
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["scope"], "complete")
        self.assertEqual(report["inventory_modules"], ["test_alpha.py", "test_beta.py"])
        self.assertEqual(report["selected_modules"], ["test_alpha.py", "test_beta.py"])
        self.assertEqual(report["requested_modules"], [])
        expected = ["test_alpha.Gate.test_alpha", "test_beta.Gate.test_beta"]
        self.assertEqual(report["collected_ids"], expected)
        self.assertEqual(report["executed_ids"], expected)
        self.assertEqual(report["counts"]["collected"], 2)
        self.assertEqual(report["counts"]["executed"], 2)
        self.assertEqual([test["status"] for test in report["tests"]], ["passed", "passed"])
        self.assertEqual([test["module"] for test in report["tests"]],
                         ["test_alpha.py", "test_beta.py"])
        self.assertEqual(report["fixture_events"], [])
        self.assertEqual(report["source_ids"]["runner_sha256"],
                         hashlib.sha256(RUNNER.read_bytes()).hexdigest())
        self.assertEqual(report["source_ids"]["modules"], {
            "test_alpha.py": hashlib.sha256(alpha.encode()).hexdigest(),
            "test_beta.py": hashlib.sha256(beta.encode()).hexdigest(),
        })
        self.assertGreaterEqual(report["collection_duration_seconds"], 0.015)
        durations = [test["duration_seconds"] for test in report["tests"]]
        self.assertTrue(all(math.isfinite(value) and value >= 0 for value in durations))
        self.assertGreaterEqual(durations[0], 0.015)
        self.assertAlmostEqual(report["summed_test_duration_seconds"], sum(durations))
        self.assertEqual(report["module_summed_test_duration_seconds"], {
            "test_alpha.py": durations[0], "test_beta.py": durations[1],
        })
        self.assertGreaterEqual(report["run_duration_seconds"] - sum(durations), 0.015)
        self.assertIn("excluding import", report["module_timing_note"])

    def test_selected_receipt_runs_exact_modules_without_importing_other_files(self):
        result = self.run_fixture(modules={
            "test_alpha.py": "import unittest\nclass Gate(unittest.TestCase):\n def test_alpha(self): pass\n",
            "test_beta.py": "import unittest\nclass Gate(unittest.TestCase):\n def test_beta(self): pass\n",
            "test_other.py": "raise RuntimeError('unselected import must not run')\n",
        }, args=("--module", "test_beta.py", "--module", "test_alpha.py"), timings=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = result.timings
        self.assertIsNotNone(report, "requested timing receipt is absent")
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["scope"], "selected")
        self.assertEqual(report["requested_modules"], ["test_beta.py", "test_alpha.py"])
        self.assertEqual(report["selected_modules"], ["test_alpha.py", "test_beta.py"])
        self.assertEqual(report["inventory_modules"],
                         ["test_alpha.py", "test_beta.py", "test_other.py"])
        self.assertEqual(report["collected_ids"],
                         ["test_alpha.Gate.test_alpha", "test_beta.Gate.test_beta"])
        self.assertEqual(report["executed_ids"], report["collected_ids"])
        self.assertEqual(set(report["source_ids"]["modules"]),
                         {"test_alpha.py", "test_beta.py"})
        self.assertIn("selected scope", result.stderr.lower())
        self.assertNotIn("unselected import must not run", result.stderr)

    def test_selected_module_does_not_traverse_nested_tests_or_package_hooks(self):
        selected_source = ("import unittest\nclass Gate(unittest.TestCase):\n"
                           " def test_top(self): pass\n")
        result = self.run_fixture(modules={
            "test_only.py": selected_source,
            "nested/__init__.py": "",
            "nested/test_only.py": ("from pathlib import Path\nimport unittest\n"
                                    "class Other(unittest.TestCase):\n"
                                    " def test_unrequested(self):\n"
                                    "  Path('nested-test.marker').write_text('executed')\n"),
            "hooked/__init__.py": (
                "from pathlib import Path\n"
                "Path('package-import.marker').write_text('imported')\n"
                "def load_tests(loader, tests, pattern):\n"
                " Path('package-hook.marker').write_text('called')\n"
                " return tests\n"),
        }, args=("--module", "test_only.py"), timings=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNotNone(result.timings, "requested timing receipt is absent")
        self.assertEqual(result.markers, {}, "selected collection imported or ran an unrelated package")
        self.assertEqual(result.timings["scope"], "selected")
        self.assertEqual(result.timings["selected_modules"], ["test_only.py"])
        self.assertEqual(result.timings["counts"]["collected"], 1)
        self.assertEqual(result.timings["collected_ids"], ["test_only.Gate.test_top"])
        self.assertEqual(result.timings["executed_ids"], ["test_only.Gate.test_top"])
        self.assertEqual([test["module"] for test in result.timings["tests"]], ["test_only.py"])
        self.assertEqual(result.timings["source_ids"]["modules"], {
            "test_only.py": hashlib.sha256(selected_source.encode()).hexdigest(),
        })

    def test_empty_selected_module_cannot_borrow_nested_same_named_tests(self):
        result = self.run_fixture(modules={
            "test_empty.py": "# no top-level tests\n",
            "nested/__init__.py": ("from pathlib import Path\n"
                                   "Path('package-import.marker').write_text('imported')\n"),
            "nested/test_empty.py": ("import unittest\nclass Other(unittest.TestCase):\n"
                                     " def test_unrequested(self): pass\n"),
        }, args=("--module", "test_empty.py"), timings=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNotNone(result.timings, "requested timing receipt is absent")
        self.assertEqual(result.timings["status"], "error")
        self.assertEqual(result.timings["executed_ids"], [])
        self.assertEqual(result.markers, {})
        self.assertIn("zero tests", result.stderr.lower())
        self.assertIn("test_empty.py", result.stderr)

    def test_complete_default_still_discovers_nested_packages(self):
        result = self.run_fixture(modules={
            "test_only.py": ("import unittest\nclass Gate(unittest.TestCase):\n"
                             " def test_top(self): pass\n"),
            "nested/__init__.py": ("from pathlib import Path\n"
                                   "Path('package-import.marker').write_text('imported')\n"),
            "nested/test_only.py": ("import unittest\nclass Other(unittest.TestCase):\n"
                                    " def test_nested(self): pass\n"),
        }, timings=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNotNone(result.timings, "requested timing receipt is absent")
        self.assertEqual(result.timings["scope"], "complete")
        self.assertEqual(result.timings["counts"]["collected"], 2)
        self.assertEqual(set(result.timings["executed_ids"]),
                         {"test_only.Gate.test_top", "nested.test_only.Other.test_nested"})
        self.assertEqual(result.markers, {"package-import.marker": "imported"})

    def test_selected_module_preserves_load_tests_and_module_class_fixtures(self):
        result = self.run_fixture(modules={"test_only.py": (
            "from pathlib import Path\nimport unittest\n"
            "def record(event):\n"
            " with Path('events.marker').open('a') as output: output.write(event + '\\n')\n"
            "def setUpModule(): record('module setup')\n"
            "def tearDownModule(): record('module teardown')\n"
            "class Gate(unittest.TestCase):\n"
            " @classmethod\n def setUpClass(cls): record('class setup')\n"
            " @classmethod\n def tearDownClass(cls): record('class teardown')\n"
            " def test_selected(self): record('selected test')\n"
            " def test_unselected(self): self.fail('load_tests was ignored')\n"
            "def load_tests(loader, tests, pattern):\n"
            " record('load_tests ' + str(pattern))\n"
            " return loader.loadTestsFromName('test_only.Gate.test_selected')\n"
        )}, args=("--module", "test_only.py"), timings=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNotNone(result.timings, "requested timing receipt is absent")
        self.assertEqual(result.timings["collected_ids"], ["test_only.Gate.test_selected"])
        self.assertEqual(result.timings["executed_ids"], ["test_only.Gate.test_selected"])
        self.assertEqual(result.markers, {"events.marker": (
            "load_tests test_only.py\nmodule setup\nclass setup\nselected test\n"
            "class teardown\nmodule teardown\n")})

    def test_selected_import_failure_cannot_exit_successfully(self):
        for body in ("raise RuntimeError('selected import error')\n", "raise SystemExit(0)\n"):
            with self.subTest(body=body):
                result = self.run_fixture(body, args=("--module", "test_fixture.py"), timings=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNotNone(result.timings, "requested timing receipt is absent")
                self.assertNotEqual(result.timings["status"], "passed")
                self.assertTrue(result.timings["collection_errors"])

    def test_selected_modules_do_not_repeat_normal_sibling_imports(self):
        result = self.run_fixture(modules={
            "test_alpha.py": ("import test_beta, unittest\nclass Alpha(unittest.TestCase):\n"
                              " def test_alpha(self): pass\n"),
            "test_beta.py": ("from pathlib import Path\nimport unittest\n"
                             "with Path('imports.marker').open('a') as output: output.write('beta\\n')\n"
                             "class Beta(unittest.TestCase):\n def test_beta(self): pass\n"),
        }, args=("--module", "test_alpha.py", "--module", "test_beta.py"), timings=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNotNone(result.timings, "requested timing receipt is absent")
        self.assertEqual(result.timings["collected_ids"],
                         ["test_alpha.Alpha.test_alpha", "test_beta.Beta.test_beta"])
        self.assertEqual(result.markers, {"imports.marker": "beta\n"})

    def test_invalid_module_selections_refuse_before_import(self):
        for name in ("", "../test_fixture.py", "/tmp/test_fixture.py", "test_*.py",
                     "test_fixture", "test_fixture.py::Gate", "test_absent.py"):
            with self.subTest(module=name):
                result = self.run_fixture("raise RuntimeError('must not collect')\n",
                                          args=("--module", name), timings=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNotNone(result.timings, "requested timing receipt is absent")
                self.assertEqual(result.timings["status"], "error")
                self.assertEqual(result.timings["scope"], "selected")
                self.assertEqual(result.timings["executed_ids"], [])
                self.assertIn("module", result.stderr.lower())
                self.assertNotIn("must not collect", result.stderr)

    def test_duplicate_module_selection_refuses_before_import(self):
        result = self.run_fixture("raise RuntimeError('must not collect')\n", timings=True,
                                  args=("--module", "test_fixture.py",
                                        "--module", "test_fixture.py"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNotNone(result.timings, "requested timing receipt is absent")
        self.assertEqual(result.timings["status"], "error")
        self.assertEqual(result.timings["executed_ids"], [])
        self.assertIn("duplicate", result.stderr.lower())
        self.assertNotIn("must not collect", result.stderr)

    def test_glob_filename_cannot_broaden_exact_module_selection(self):
        result = self.run_fixture(modules={
            "test_[ab].py": "# not an importable Python module name\n",
            "test_a.py": "raise RuntimeError('must not collect another module')\n",
        }, args=("--module", "test_[ab].py"), timings=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNotNone(result.timings, "requested timing receipt is absent")
        self.assertEqual(result.timings["status"], "error")
        self.assertEqual(result.timings["executed_ids"], [])
        self.assertNotIn("must not collect another module", result.stderr)

    def test_empty_selected_module_cannot_hide_beside_a_nonempty_module(self):
        result = self.run_fixture(modules={
            "test_empty.py": "# no tests\n",
            "test_good.py": "import unittest\nclass Gate(unittest.TestCase):\n def test_pass(self): pass\n",
        }, args=("--module", "test_empty.py", "--module", "test_good.py"), timings=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNotNone(result.timings, "requested timing receipt is absent")
        self.assertEqual(result.timings["status"], "error")
        self.assertEqual(result.timings["executed_ids"], [])
        self.assertIn("zero tests", result.stderr.lower())
        self.assertIn("test_empty.py", result.stderr)

    def test_failure_receipt_retains_all_executed_test_timings(self):
        result = self.run_fixture("import unittest\nclass Gate(unittest.TestCase):\n"
                                  " def test_a_pass(self): pass\n"
                                  " def test_b_fail(self): self.fail('fixture failure')\n",
                                  timings=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNotNone(result.timings, "requested timing receipt is absent")
        report = result.timings
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["counts"]["executed"], 2)
        self.assertEqual(report["counts"]["failures"], 1)
        self.assertEqual(report["executed_ids"],
                         ["test_fixture.Gate.test_a_pass", "test_fixture.Gate.test_b_fail"])
        self.assertEqual([test["status"] for test in report["tests"]], ["passed", "failed"])
        self.assertTrue(all(test["duration_seconds"] >= 0 for test in report["tests"]))
        self.assertIn("fixture failure", report["tests"][1]["detail"])

    def test_partial_execution_cannot_claim_a_passing_scope(self):
        result = self.run_fixture("import unittest\nclass Gate(unittest.TestCase):\n"
                                  " def test_a_stop(self): self._outcome.result.stop()\n"
                                  " def test_b_unexecuted(self): pass\n", timings=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNotNone(result.timings, "requested timing receipt is absent")
        self.assertEqual(result.timings["status"], "failed")
        self.assertEqual(result.timings["counts"]["collected"], 2)
        self.assertEqual(result.timings["counts"]["executed"], 1)
        self.assertEqual(result.timings["executed_ids"], ["test_fixture.Gate.test_a_stop"])
        self.assertIn("incomplete execution", result.stderr.lower())

    def test_zero_execution_cannot_pass_with_nonzero_collection(self):
        result = self.run_fixture("import unittest\n"
                                  "class NoWork(unittest.TestSuite):\n"
                                  " def run(self, result, debug=False): return result\n"
                                  "def load_tests(loader, tests, pattern): return NoWork(tests)\n"
                                  "class Gate(unittest.TestCase):\n def test_pass(self): pass\n",
                                  timings=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNotNone(result.timings, "requested timing receipt is absent")
        self.assertEqual(result.timings["status"], "failed")
        self.assertEqual(result.timings["counts"]["collected"], 1)
        self.assertEqual(result.timings["counts"]["executed"], 0)
        self.assertEqual(result.timings["executed_ids"], [])
        self.assertIn("incomplete execution", result.stderr.lower())

    def test_skip_receipt_cannot_claim_success(self):
        result = self.run_fixture("import unittest\nclass Gate(unittest.TestCase):\n"
                                  " def test_skip(self): self.skipTest('fixture skip')\n",
                                  timings=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNotNone(result.timings, "requested timing receipt is absent")
        self.assertEqual(result.timings["status"], "failed")
        self.assertEqual(result.timings["counts"]["skipped"], 1)
        self.assertEqual(result.timings["tests"][0]["status"], "skipped")
        self.assertEqual(result.timings["tests"][0]["detail"], "fixture skip")

    def test_subtest_outcomes_are_preserved_and_fail_the_gate(self):
        result = self.run_fixture("import unittest\nclass Gate(unittest.TestCase):\n"
                                  " def test_parts(self):\n"
                                  "  with self.subTest(part='pass'): pass\n"
                                  "  with self.subTest(part='fail'): self.fail('subtest failure')\n"
                                  "  with self.subTest(part='error'): raise ValueError('subtest error')\n"
                                  "  with self.subTest(part='skip'): self.skipTest('subtest skip')\n",
                                  timings=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNotNone(result.timings, "requested timing receipt is absent")
        report = result.timings
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["counts"]["collected"], 1)
        self.assertEqual(report["counts"]["executed"], 1)
        self.assertEqual(report["counts"]["failures"], 1)
        self.assertEqual(report["counts"]["errors"], 1)
        self.assertEqual(report["counts"]["skipped"], 1)
        test = report["tests"][0]
        self.assertEqual(test["status"], "error")
        self.assertEqual([event["status"] for event in test["subtests"]],
                         ["passed", "failed", "error", "skipped"])
        self.assertEqual([event["id"] for event in test["subtests"]], [
            "test_fixture.Gate.test_parts (part='pass')",
            "test_fixture.Gate.test_parts (part='fail')",
            "test_fixture.Gate.test_parts (part='error')",
            "test_fixture.Gate.test_parts (part='skip')",
        ])
        self.assertEqual(report["fixture_events"], [])

    def test_unexpected_success_is_visible_and_cannot_pass(self):
        result = self.run_fixture("import unittest\nclass Gate(unittest.TestCase):\n"
                                  " @unittest.expectedFailure\n def test_fixed(self): pass\n",
                                  timings=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNotNone(result.timings, "requested timing receipt is absent")
        self.assertEqual(result.timings["status"], "failed")
        self.assertEqual(result.timings["counts"]["unexpected_successes"], 1)
        self.assertEqual(result.timings["tests"][0]["status"], "unexpected_success")

    def test_expected_failure_retains_existing_gate_semantics(self):
        result = self.run_fixture("import unittest\nclass Gate(unittest.TestCase):\n"
                                  " @unittest.expectedFailure\n"
                                  " def test_known(self): self.fail('known failure')\n",
                                  timings=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNotNone(result.timings, "requested timing receipt is absent")
        self.assertEqual(result.timings["status"], "passed")
        self.assertEqual(result.timings["counts"]["expected_failures"], 1)
        self.assertEqual(result.timings["tests"][0]["status"], "expected_failure")

    def test_fixture_error_holders_have_events_without_fabricated_test_runs(self):
        fixtures = {
            "setUpClass": ("import unittest\nclass Gate(unittest.TestCase):\n"
                           " @classmethod\n def setUpClass(cls): raise RuntimeError('fixture setup')\n"
                           " def test_pass(self): pass\n", 0),
            "tearDownClass": ("import unittest\nclass Gate(unittest.TestCase):\n"
                              " @classmethod\n def tearDownClass(cls): raise RuntimeError('fixture teardown')\n"
                              " def test_pass(self): pass\n", 1),
            "setUpModule": ("import unittest\n"
                            "def setUpModule(): raise RuntimeError('module setup')\n"
                            "class Gate(unittest.TestCase):\n def test_pass(self): pass\n", 0),
            "tearDownModule": ("import unittest\n"
                               "def tearDownModule(): raise RuntimeError('module teardown')\n"
                               "class Gate(unittest.TestCase):\n def test_pass(self): pass\n", 1),
        }
        for event_name, (body, executed) in fixtures.items():
            with self.subTest(fixture=event_name):
                result = self.run_fixture(body, timings=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNotNone(result.timings, "requested timing receipt is absent")
                report = result.timings
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["counts"]["collected"], 1)
                self.assertEqual(report["counts"]["executed"], executed)
                self.assertEqual(report["counts"]["errors"], 1)
                self.assertEqual(len(report["executed_ids"]), executed)
                self.assertEqual(len(report["fixture_events"]), 1)
                event = report["fixture_events"][0]
                self.assertTrue(event["id"].startswith(event_name + " ("))
                self.assertEqual(event["status"], "error")
                self.assertNotIn("duration_seconds", event)

    def test_import_error_receipt_retains_collection_failure(self):
        result = self.run_fixture("raise RuntimeError('fixture import error')\n", timings=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNotNone(result.timings, "requested timing receipt is absent")
        self.assertEqual(result.timings["status"], "failed")
        self.assertEqual(result.timings["counts"]["errors"], 1)
        self.assertTrue(result.timings["collection_errors"])
        self.assertIn("fixture import error", "\n".join(result.timings["collection_errors"]))
        self.assertEqual(result.timings["tests"][0]["status"], "error")

    def test_zero_work_and_missing_prerequisites_leave_nonpassing_receipts(self):
        cases = ((None, {}), ("raise RuntimeError('must not collect')\n", {"path": ""}),
                 ("raise RuntimeError('must not collect')\n", {"no_site": True}),
                 ("raise RuntimeError('must not collect')\n", {"yaml_version": "0.0.0"}))
        for body, options in cases:
            with self.subTest(options=options):
                result = self.run_fixture(body, timings=True, stale_receipt=True, **options)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNotNone(result.timings, "requested timing receipt is absent")
                self.assertEqual(result.timings["status"], "error")
                self.assertEqual(result.timings["executed_ids"], [])
                self.assertNotIn("old", result.timings)
                self.assertNotIn("must not collect", result.stderr)

    def test_malformed_arguments_replace_old_success_before_import(self):
        body = ("from pathlib import Path\nimport unittest\n"
                "Path('import.marker').write_text('imported')\n"
                "class Gate(unittest.TestCase):\n"
                " def test_run(self): Path('execution.marker').write_text('executed')\n")
        for args in (("--module",), ("--unknown-option",)):
            with self.subTest(args=args):
                result = self.run_fixture(body, args=args, timings=True, stale_receipt=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIsNotNone(result.timings, "requested timing receipt is absent")
                self.assertNotEqual(result.timings["status"], "passed")
                self.assertNotIn("old", result.timings)
                self.assertEqual(result.timings["counts"]["collected"], 0)
                self.assertEqual(result.timings["counts"]["executed"], 0)
                self.assertEqual(result.timings["collected_ids"], [])
                self.assertEqual(result.timings["executed_ids"], [])
                self.assertEqual(result.timings["tests"], [])
                self.assertEqual(result.timings["source_ids"]["runner_sha256"],
                                 hashlib.sha256(RUNNER.read_bytes()).hexdigest())
                self.assertEqual(result.markers, {})

    def test_help_preserves_old_success_without_import(self):
        for option in ("-h", "--help"):
            for timings in (False, True):
                with self.subTest(option=option, timings=timings):
                    result = self.run_fixture(
                        "from pathlib import Path\nPath('import.marker').write_text('imported')\n",
                        args=(option,), timings=timings, stale_receipt=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("--module", result.stdout)
                    self.assertIn("--timings-json", result.stdout)
                    self.assertEqual(result.timings, {"status": "passed", "old": True})
                    self.assertEqual(result.markers, {})

    def test_ambiguous_or_unknown_timing_arguments_do_not_choose_an_output(self):
        for timings, args in (
            (True, ("--timings-json",)),
            (True, ("--timings-json", "timings.json")),
            (False, ("--timings-jso", "timings.json")),
            (False, ("--timings-json-unknown", "timings.json")),
        ):
            with self.subTest(timings=timings, args=args):
                result = self.run_fixture(
                    "from pathlib import Path\nPath('import.marker').write_text('imported')\n",
                    args=args, timings=timings, stale_receipt=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.timings, {"status": "passed", "old": True})
                self.assertEqual(result.markers, {})

    def test_initial_receipt_write_failure_refuses_before_import(self):
        result = self.run_fixture("raise RuntimeError('must not collect')\n", timings=True,
                                  receipt_directory=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("timing receipt", result.stderr.lower())
        self.assertNotIn("must not collect", result.stderr)

    def test_final_receipt_write_failure_overrides_successful_tests(self):
        result = self.run_fixture("import pathlib, unittest\nclass Gate(unittest.TestCase):\n"
                                  " def test_break_output(self):\n"
                                  "  path = pathlib.Path('timings.json')\n"
                                  "  path.unlink()\n  path.mkdir()\n", timings=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Ran 1 test", result.stderr)
        self.assertIn("timing receipt", result.stderr.lower())

    def test_interrupt_replaces_old_success_and_keeps_partial_execution(self):
        result = self.run_fixture("import unittest\nclass Gate(unittest.TestCase):\n"
                                  " def test_a_pass(self): pass\n"
                                  " def test_b_interrupt(self): raise KeyboardInterrupt\n"
                                  " def test_c_unexecuted(self): pass\n", timings=True,
                                  stale_receipt=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNotNone(result.timings, "requested timing receipt is absent")
        report = result.timings
        self.assertEqual(report["status"], "interrupted")
        self.assertNotIn("old", report)
        self.assertEqual(report["counts"]["collected"], 3)
        self.assertEqual(report["counts"]["executed"], 2)
        self.assertEqual([test["status"] for test in report["tests"]], ["passed", "incomplete"])
        self.assertTrue(all(test["duration_seconds"] >= 0 for test in report["tests"]))

    def test_abrupt_exit_cannot_leave_a_prior_passing_receipt(self):
        result = self.run_fixture("import os, unittest\nclass Gate(unittest.TestCase):\n"
                                  " def test_exit(self): os._exit(7)\n", timings=True,
                                  stale_receipt=True)
        self.assertEqual(result.returncode, 7)
        self.assertIsNotNone(result.timings, "requested timing receipt is absent")
        self.assertEqual(result.timings["status"], "running")
        self.assertNotIn("old", result.timings)
        self.assertEqual(result.timings["collected_ids"], ["test_fixture.Gate.test_exit"])


class FeedbackWorkflowTests(unittest.TestCase):
    def test_feedback_jobs_are_required_for_pr_and_publication(self):
        jobs = workflow()["jobs"]
        for job_id in ("script-regressions", "native-contracts", "package-consumers"):
            with self.subTest(job=job_id):
                self.assertIn(job_id, jobs)
                self.assertIn(job_id, jobs["ci-success"]["needs"])
                self.assertNotIn("if", jobs[job_id])
                self.assertNotIn("continue-on-error", jobs[job_id])

    def test_script_gate_installs_pinned_dependencies_and_full_history(self):
        job = workflow()["jobs"].get("script-regressions", {})
        steps = job.get("steps", [])
        checkouts = [step for step in steps if "actions/checkout@" in step.get("uses", "")]
        self.assertTrue(checkouts)
        self.assertEqual(checkouts[0].get("with", {}).get("fetch-depth"), 0)
        setups = [step for step in steps if "actions/setup-python@" in step.get("uses", "")]
        self.assertEqual(len(setups), 1)
        self.assertEqual(setups[0]["with"]["python-version"], "3.12")
        commands = "\n".join(step.get("run", "") for step in steps)
        self.assertIn("-r requirements-script-tests.txt", commands)
        self.assertIn("python3 scripts/run-script-tests.py", commands)
        self.assertNotIn("|| true", commands)
        self.assertNotIn("--pattern", commands)

    def test_script_gate_toolchain_covers_toolchain_file_components(self):
        # Fix round 1 (F2a): the suite runs `cargo metadata` under the
        # repo root, so rust-toolchain.toml's components must be
        # preinstalled in the job — otherwise the first cargo invocation
        # triggers a test-time rustup component install, which fails on
        # a fresh minimal toolchain (`conflict: bin/cargo-fmt`) and
        # errors test_package_manifests.setUpClass.
        job = workflow()["jobs"].get("script-regressions", {})
        toolchains = [step for step in job.get("steps", [])
                      if "dtolnay/rust-toolchain@" in step.get("uses", "")]
        self.assertEqual(len(toolchains), 1)
        installed = {component.strip() for component in
                     toolchains[0].get("with", {}).get("components", "").split(",")}
        installed.discard("")
        with (ROOT / "rust-toolchain.toml").open("rb") as handle:
            required = set(tomllib.load(handle)["toolchain"]["components"])
        self.assertTrue(required, "rust-toolchain.toml should require components")
        self.assertTrue(
            required <= installed,
            f"script-regressions preinstalls {sorted(installed)}; "
            f"rust-toolchain.toml requires {sorted(required)}",
        )

    def test_native_gate_uses_strict_receipt_runner(self):
        job = workflow()["jobs"].get("native-contracts", {})
        text = yaml.safe_dump(job)
        self.assertIn("python3 scripts/run-native-contracts.py --output", text)
        self.assertIn("protoc", text)
        self.assertIn("1.98.1", text)
        self.assertNotIn("continue-on-error", text)

    def test_package_consumers_overlap_archive_builds(self):
        jobs = workflow()["jobs"]
        consumer = jobs.get("package-consumers", {})
        self.assertEqual(consumer.get("needs"), "package-candidate")
        text = yaml.safe_dump(consumer)
        self.assertIn("release_checks.py consumer", text)
        self.assertIn("--toolchain 1.88.0", text)
        self.assertIn("release_checks.py archives", text)
        for job_id in ("archive-binary-linux", "archive-binary-windows", "archive-binary-macos"):
            self.assertEqual(jobs[job_id]["needs"], "package-candidate")
        candidate_commands = "\n".join(step.get("run", "")
                                       for step in jobs["package-candidate"]["steps"])
        self.assertNotIn("release_checks.py consumer", candidate_commands)

    def test_consumer_downloads_exact_artifact_and_checks_recorded_hashes(self):
        consumer = workflow()["jobs"].get("package-consumers", {})
        downloads = [step for step in consumer.get("steps", [])
                     if "actions/download-artifact@" in step.get("uses", "")]
        self.assertEqual(len(downloads), 1)
        self.assertEqual(downloads[0]["with"]["name"],
                         "ci-candidate-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}")
        text = yaml.safe_dump(consumer)
        self.assertIn("sha256sum -c SHA256SUMS", text)
        self.assertIn("CARGO_TARGET_DIR", text)
        self.assertIn("CARGO_BUILD_BUILD_DIR", text)
        self.assertNotIn("actions/cache", text)

    def test_cross_platform_cancels_only_obsolete_pull_requests(self):
        concurrency = workflow("cross-platform").get("concurrency", {})
        self.assertTrue(str(concurrency.get("group", "")).startswith("cross-platform-"))
        self.assertIn("github.ref", concurrency.get("group", ""))
        self.assertIn("github.event_name", concurrency.get("group", ""))
        # GitHub replaces an older pending member of a concurrency group even
        # when cancel-in-progress is false. Non-PR runs need unique groups.
        self.assertIn("github.event_name == 'pull_request' && github.ref || github.run_id",
                      concurrency.get("group", ""))
        self.assertEqual(concurrency.get("cancel-in-progress"),
                         "${{ github.event_name == 'pull_request' }}")


if __name__ == "__main__":
    unittest.main()

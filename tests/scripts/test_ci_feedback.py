"""Required feedback scheduling and fail-closed script-runner contracts."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/run-script-tests.py"


def workflow(name="ci"):
    return yaml.safe_load((ROOT / f".github/workflows/{name}.yml").read_text())


class ScriptRunnerTests(unittest.TestCase):
    def run_fixture(self, body, *, path=None, no_site=False, yaml_version=None):
        # Copy the real entrypoint into a standalone repository fixture; there
        # is deliberately no production CLI for narrowing the required suite.
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
            if body is not None:
                (root / "tests/scripts/test_fixture.py").write_text(body)
            env = dict(os.environ)
            env.pop("PYTHONPATH", None)
            if path is not None:
                env["PATH"] = path
            command = [sys.executable]
            if no_site:
                command.append("-S")
            command.append(str(root / "scripts/run-script-tests.py"))
            return subprocess.run(command, cwd=root, env=env, text=True,
                                  capture_output=True, timeout=30)

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

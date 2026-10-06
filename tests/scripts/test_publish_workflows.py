"""Stage B (Task 5a) workflow and artifact-smoke contract tests.

RED-FIRST: these tests describe the required reusable GitHub CI
(``.github/workflows/ci.yml``) and the reusable artifact-smoke contract
(``scripts/ci-package-smoke.py``). They fail until the workflow gains
``workflow_call``, the package/archive/binary/notice checks, the three
required artifact-smoke lanes, and the fail-closed aggregate.

Stage C (Task 5b) extends this module for ``publish.yml`` /
``publish-staging.yml`` / ``release.yml``; Stage B asserts the CI side only.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - test env provides PyYAML
    yaml = None

ROOT = Path(__file__).resolve().parents[2]
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
OPENRC = ROOT / "packaging" / "alpine" / "pkcs11-proxy-ng-daemon.openrc"
SYSTEMD_UNIT = ROOT / "packaging" / "amazon" / "pkcs11-proxy-ng.service"
SMOKE_SCRIPT = ROOT / "scripts" / "ci-package-smoke.py"
COMPARE_SCRIPT = ROOT / "scripts" / "ci-direct-vs-proxy.py"

EXISTING_JOBS = (
    "fmt",
    "audit",
    "deny",
    "packaging-smoke",
    "shellcheck",
    "build-and-test",
    "msrv",
    "narrow-client-i686",
    "windows-client-llp64",
    "musl-x86_64",
)
NEW_REQUIRED_JOBS = (
    "package-candidate",
    "archive-binary-linux",
    "archive-binary-windows",
    "archive-binary-macos",
    "smoke-apk-alpine",
    "smoke-bundle-linux",
    "smoke-bundle-windows",
    "smoke-bundle-macos",
)
AGGREGATE_JOB = "ci-success"
REQUIRED_JOBS = EXISTING_JOBS + NEW_REQUIRED_JOBS

RELEASE_RUST = "1.98.1"
MSRV = "1.88.0"
PROTOC = "36.2"
SOFTHSM_WIN_SHA256 = (
    "85273BCC1A6B90E877F7BB4F7E90221D57103D8F5241D154A79DD730A135B910"
)


def load_workflow():
    if yaml is None:
        raise unittest.SkipTest("PyYAML is required to parse ci.yml")
    return yaml.safe_load(CI_YML.read_text(encoding="utf-8"))


def workflow_triggers(workflow):
    # YAML 1.1 parses the `on:` key as boolean True; accept either form.
    triggers = workflow.get("on", workflow.get(True, {}))
    return triggers if isinstance(triggers, dict) else {}


def job_text(job_id, workflow=None):
    workflow = workflow if workflow is not None else load_workflow()
    job = workflow["jobs"][job_id]
    return yaml.safe_dump(job, default_flow_style=False)


def load_release_refs():
    module_name = "package_refs_under_test"
    # package_refs.py uses a relative import; load its package properly.
    package_dir = str(ROOT / "scripts")
    if package_dir not in sys.path:
        sys.path.insert(0, package_dir)
    import release.package_refs as refs

    sys.modules[module_name] = refs
    return refs


class ExistingJobsPreservedTests(unittest.TestCase):
    def test_ten_existing_jobs_remain(self):
        workflow = load_workflow()
        jobs = workflow["jobs"]
        for job_id in EXISTING_JOBS:
            with self.subTest(job=job_id):
                self.assertIn(job_id, jobs)

    def test_clippy_stays_inside_build_and_test(self):
        workflow = load_workflow()
        self.assertIn("clippy", job_text("build-and-test", workflow))
        self.assertNotIn("clippy", workflow["jobs"])

    def test_cross_platform_workflow_preserved(self):
        xplat = ROOT / ".github" / "workflows" / "cross-platform.yml"
        text = xplat.read_text(encoding="utf-8")
        self.assertIn("Direct-vs-proxied comparison", text)
        self.assertIn("KAT", text)


class ReusableTriggerTests(unittest.TestCase):
    def test_workflow_call_enabled(self):
        workflow = load_workflow()
        self.assertIn("workflow_call", workflow_triggers(workflow))

    def test_pr_trigger_preserved(self):
        workflow = load_workflow()
        self.assertIn("pull_request", workflow_triggers(workflow))

    def test_same_gates_for_pr_and_publication_calls(self):
        """No job may gate on the event name: PR and workflow_call runs
        execute the identical required set (the aggregate is the only
        job-level `if`, and it is `always()`)."""
        workflow = load_workflow()
        for job_id, job in workflow["jobs"].items():
            with self.subTest(job=job_id):
                condition = job.get("if", "")
                if job_id == AGGREGATE_JOB:
                    self.assertEqual(condition, "always()")
                else:
                    self.assertNotIn("github.event_name", str(condition))
                    self.assertFalse(
                        str(condition).strip(),
                        f"job {job_id} must not gate execution by event",
                    )

    def test_concurrency_uses_separate_namespace(self):
        workflow = load_workflow()
        concurrency = workflow.get("concurrency", {})
        group = str(concurrency.get("group", ""))
        self.assertTrue(group, "ci.yml must keep an explicit concurrency group")
        self.assertIn("ci-", group)
        self.assertNotEqual(group, "${{ github.workflow }}-${{ github.ref }}")
        self.assertEqual(
            str(concurrency.get("cancel-in-progress")),
            "${{ github.event_name == 'pull_request' }}",
        )


class AggregateTests(unittest.TestCase):
    def test_new_required_jobs_defined(self):
        workflow = load_workflow()
        for job_id in NEW_REQUIRED_JOBS:
            with self.subTest(job=job_id):
                self.assertIn(job_id, workflow["jobs"])

    def test_aggregate_lists_every_required_job(self):
        workflow = load_workflow()
        self.assertIn(AGGREGATE_JOB, workflow["jobs"])
        needs = workflow["jobs"][AGGREGATE_JOB].get("needs", [])
        for job_id in REQUIRED_JOBS:
            with self.subTest(job=job_id):
                self.assertIn(job_id, needs)
        self.assertNotIn(AGGREGATE_JOB, needs)

    def test_aggregate_is_fail_closed_always(self):
        workflow = load_workflow()
        aggregate = workflow["jobs"][AGGREGATE_JOB]
        self.assertEqual(aggregate.get("if"), "always()")
        text = job_text(AGGREGATE_JOB, workflow)
        self.assertIn("ci-results", text)
        self.assertIn("toJSON(needs)", text)

    def test_all_real_jobs_set_timeouts(self):
        workflow = load_workflow()
        for job_id, job in workflow["jobs"].items():
            with self.subTest(job=job_id):
                if "uses" in job:
                    continue  # reusable-call jobs follow GitHub's own schema
                timeout = job.get("timeout-minutes")
                self.assertIsInstance(timeout, int)
                self.assertGreaterEqual(timeout, 5)
                self.assertLessEqual(timeout, 120)


class CiResultsRefusalTests(unittest.TestCase):
    def test_success_passes(self):
        refs = load_release_refs()
        count = refs.verify_ci_results('{"a": {"result": "success"}}')
        self.assertEqual(count, 1)

    def test_skipped_cancelled_failure_refuse(self):
        refs = load_release_refs()
        for result in ("skipped", "cancelled", "failure"):
            with self.subTest(result=result):
                with self.assertRaises(Exception):
                    refs.verify_ci_results(f'{{"a": {{"result": "{result}"}}}}')

    def test_missing_or_empty_needs_refuse(self):
        refs = load_release_refs()
        for payload in ("{}", "[]", "null", "not-json"):
            with self.subTest(payload=payload):
                with self.assertRaises(Exception):
                    refs.verify_ci_results(payload)


class PackageCandidateTests(unittest.TestCase):
    def test_pins(self):
        text = CI_YML.read_text(encoding="utf-8")
        self.assertIn(RELEASE_RUST, text)
        self.assertIn(MSRV, text)
        self.assertIn(f'version: "{PROTOC}"', text)
        self.assertIn("--toolchain 1.98.1", text)

    def test_package_candidate_runs_archive_and_consumer_gates(self):
        workflow = load_workflow()
        text = job_text("package-candidate", workflow)
        self.assertIn("cargo", text)
        self.assertIn("package", text)
        self.assertIn("release_checks.py", text)
        self.assertIn("archives", text)
        self.assertIn("consumer", text)

    def test_candidate_artifact_identifies_source(self):
        workflow = load_workflow()
        text = job_text("package-candidate", workflow)
        self.assertIn("upload-artifact", text)
        self.assertIn("github.sha", text)
        self.assertIn("github.run_id", text)

    def test_cargo_build_and_target_dirs_isolated(self):
        workflow = load_workflow()
        for job_id in ("package-candidate", "archive-binary-linux",
                       "archive-binary-windows", "archive-binary-macos"):
            with self.subTest(job=job_id):
                text = job_text(job_id, workflow)
                self.assertIn("CARGO_BUILD_BUILD_DIR", text)
                self.assertIn("CARGO_TARGET_DIR", text)

    def test_no_shared_crate_caches(self):
        workflow = load_workflow()
        for job_id in NEW_REQUIRED_JOBS:
            with self.subTest(job=job_id):
                text = job_text(job_id, workflow)
                self.assertNotIn("actions/cache", text)
                self.assertNotIn(".crate", text.split("upload-artifact")[0]
                                 if "upload-artifact" in text else text)


class BinaryNoticeBundleTests(unittest.TestCase):
    def test_archive_mode_builds_for_all_targets(self):
        text = CI_YML.read_text(encoding="utf-8")
        for target in ("x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
                       "aarch64-apple-darwin"):
            with self.subTest(target=target):
                self.assertIn(f"binary-build --source archive --target {target}", text)

    def test_notice_and_bundle_checks_present(self):
        text = CI_YML.read_text(encoding="utf-8")
        self.assertIn("notices --build-inputs", text)
        self.assertIn("bundle --binaries", text)

    def test_downstream_jobs_consume_source_bound_candidate(self):
        workflow = load_workflow()
        for job_id in ("archive-binary-linux", "archive-binary-windows",
                       "archive-binary-macos"):
            with self.subTest(job=job_id):
                text = job_text(job_id, workflow)
                self.assertIn("download-artifact", text)
                self.assertIn("github.sha", text)
                self.assertIn("ci-candidate-", text)

    def test_smoke_jobs_consume_matching_bundle_artifact(self):
        workflow = load_workflow()
        for job_id, artifact in (("smoke-bundle-linux", "ci-linux-bundle-"),
                                 ("smoke-bundle-windows", "ci-windows-bundle-"),
                                 ("smoke-bundle-macos", "ci-macos-bundle-")):
            with self.subTest(job=job_id):
                text = job_text(job_id, workflow)
                self.assertIn("download-artifact", text)
                self.assertIn(artifact, text)
                self.assertIn("github.sha", text)


class SmokeLaneTests(unittest.TestCase):
    def test_required_smoke_lanes_are_present(self):
        workflow = load_workflow()
        needs = workflow["jobs"][AGGREGATE_JOB].get("needs", [])
        for job_id in ("smoke-apk-alpine", "smoke-bundle-linux",
                       "smoke-bundle-windows", "smoke-bundle-macos"):
            with self.subTest(job=job_id):
                self.assertIn(job_id, workflow["jobs"])
                self.assertIn(job_id, needs)

    def test_windows_lane_is_native(self):
        workflow = load_workflow()
        runs_on = str(workflow["jobs"]["smoke-bundle-windows"].get("runs-on"))
        self.assertIn("windows", runs_on)

    def test_macos_lane_is_native(self):
        workflow = load_workflow()
        runs_on = str(workflow["jobs"]["smoke-bundle-macos"].get("runs-on"))
        self.assertIn("macos", runs_on)

    def test_smoke_lanes_use_reusable_contract(self):
        workflow = load_workflow()
        for job_id in ("smoke-apk-alpine", "smoke-bundle-linux",
                       "smoke-bundle-windows", "smoke-bundle-macos"):
            with self.subTest(job=job_id):
                self.assertIn("ci-package-smoke.py",
                              job_text(job_id, workflow))

    def test_smoke_lanes_pass_exact_artifact_paths(self):
        workflow = load_workflow()
        self.assertIn("--apk-dir", job_text("smoke-apk-alpine", workflow))
        self.assertIn("--bundle", job_text("smoke-bundle-linux", workflow))
        self.assertIn("--bundle", job_text("smoke-bundle-windows", workflow))
        self.assertIn("--bundle", job_text("smoke-bundle-macos", workflow))

    def test_no_workspace_binary_fallback(self):
        workflow = load_workflow()
        for job_id in ("smoke-apk-alpine", "smoke-bundle-linux",
                       "smoke-bundle-windows", "smoke-bundle-macos"):
            with self.subTest(job=job_id):
                text = job_text(job_id, workflow)
                self.assertNotIn("target/release", text)
                self.assertNotIn("cargo build", text)
        self.assertTrue(SMOKE_SCRIPT.is_file())
        self.assertNotIn("target/release",
                         SMOKE_SCRIPT.read_text(encoding="utf-8"))

    def test_apk_lane_covers_individual_install_remove(self):
        workflow = load_workflow()
        steps = workflow["jobs"]["smoke-apk-alpine"]["steps"]
        indiv = [s for s in steps
                 if "ndividual" in str(s.get("name", ""))]
        self.assertEqual(len(indiv), 1)
        run = str(indiv[0].get("run", ""))
        for package in ("pkcs11-proxy-ng-shim", "pkcs11-proxy-ng-daemon",
                        "pkcs11-proxy-ng-cli", "pkcs11-proxy-ng-compat"):
            with self.subTest(package=package):
                self.assertIn(package, run)
        self.assertIn("apk del", run)
        # The all-together install + provider smoke must remain alongside.
        smoke = [s for s in steps if "provider smoke" in str(s.get("name", ""))]
        self.assertEqual(len(smoke), 1)
        self.assertIn("installed-smoke", str(smoke[0].get("run", "")))

    def test_apk_lane_verifies_installed_hashes(self):
        workflow = load_workflow()
        steps = workflow["jobs"]["smoke-apk-alpine"]["steps"]
        verify = [s for s in steps if "Verify APK set" in str(s.get("name", ""))]
        self.assertEqual(len(verify), 1)
        self.assertIn("--hash-output", str(verify[0].get("run", "")))
        smoke = [s for s in steps if "provider smoke" in str(s.get("name", ""))]
        self.assertEqual(len(smoke), 1)
        run = str(smoke[0].get("run", ""))
        self.assertIn("installed-verify", run)
        self.assertIn("--expected-hashes", run)
        self.assertIn("--record-out", run)

    def test_apk_export_passes_command_to_docker_create(self):
        # The carrier image is FROM scratch with no CMD, so `docker create`
        # without an explicit command fails ("no command specified").
        # create/cp/rm never execute it, so any argv keeps export working.
        workflow = load_workflow()
        steps = workflow["jobs"]["smoke-apk-alpine"]["steps"]
        extract = [s for s in steps
                   if "Extract APK set" in str(s.get("name", ""))]
        self.assertEqual(len(extract), 1)
        creates = [line for line in str(extract[0].get("run", "")).splitlines()
                   if "docker create" in line]
        self.assertEqual(len(creates), 1)
        self.assertRegex(creates[0], r'docker create\s+"[^"]+"\s+\S+')

    def test_smoke_proves_provider_operations_not_help(self):
        self.assertTrue(SMOKE_SCRIPT.is_file())
        text = SMOKE_SCRIPT.read_text(encoding="utf-8")
        for marker in ("C_OpenSession", "C_Login", "C_GenerateKey", "C_Sign"):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_windows_softhsm_pin_reused(self):
        self.assertTrue(SMOKE_SCRIPT.is_file())
        text = SMOKE_SCRIPT.read_text(encoding="utf-8")
        self.assertIn(SOFTHSM_WIN_SHA256, text)
        compare = COMPARE_SCRIPT.read_text(encoding="utf-8")
        self.assertIn(SOFTHSM_WIN_SHA256, compare)

    def test_provider_smoke_raises_memlock_limit(self):
        # The smoke container runs the mlockall daemon directly: under
        # MCL_FUTURE every thread-stack mmap charges RLIMIT_MEMLOCK, and
        # the container default fails the first worker spawn with EAGAIN.
        workflow = load_workflow()
        steps = workflow["jobs"]["smoke-apk-alpine"]["steps"]
        smoke = [s for s in steps
                 if "provider smoke" in str(s.get("name", ""))]
        self.assertEqual(len(smoke), 1)
        run = str(smoke[0].get("run", ""))
        self.assertIn("--ulimit memlock=", run)

    def test_apk_smoke_fixes_workdir_ownership_before_upload(self):
        # The smoke container runs as root; without a fixup the
        # always-run evidence upload (runner user) fails EACCES on
        # root-owned token files.
        workflow = load_workflow()
        steps = workflow["jobs"]["smoke-apk-alpine"]["steps"]
        names = [str(s.get("name", "")) for s in steps]
        fixup = [i for i, name in enumerate(names) if "ownership" in name]
        upload = [i for i, name in enumerate(names)
                  if "Upload APK smoke evidence" in name]
        self.assertEqual(len(fixup), 1)
        self.assertEqual(len(upload), 1)
        self.assertLess(fixup[0], upload[0])
        self.assertEqual(steps[fixup[0]].get("if"), "always()")
        self.assertIn("chmod -R a+rwX", str(steps[fixup[0]].get("run", "")))


class ServiceMemlockTests(unittest.TestCase):
    """Packaged services must grant the mlockall daemon memlock headroom.

    Same root cause as the CI smoke failure: thread-stack mmaps charge
    RLIMIT_MEMLOCK under MCL_FUTURE, so the service defaults crash the
    daemon at its first worker spawn. The runbook already requires this
    (doc/runbooks/operating-pkcs11-proxy-ng.md "Memory lock and swap").
    """

    def test_openrc_raises_memlock_limit(self):
        lines = [line for line in
                 OPENRC.read_text(encoding="utf-8").splitlines()
                 if line.startswith("rc_ulimit=")]
        self.assertEqual(len(lines), 1)
        self.assertIn("-l unlimited", lines[0])

    def test_systemd_sets_limit_memlock(self):
        text = SYSTEMD_UNIT.read_text(encoding="utf-8")
        self.assertIn("LimitMEMLOCK=infinity", text)


class ShellHygieneTests(unittest.TestCase):
    def test_shellcheck_step_uses_quoted_array(self):
        text = CI_YML.read_text(encoding="utf-8")
        self.assertIn('"${', text)
        self.assertRegex(text, r'mapfile -t \w+ < <\(.*find.*\.sh')
        self.assertNotIn("shellcheck -x $(find", text)

    def test_musl_link_flags_separate_export(self):
        text = CI_YML.read_text(encoding="utf-8")
        self.assertNotIn('export RUSTFLAGS="$(', text)
        self.assertIn("musl-dynamic-link-flags.sh", text)


if __name__ == "__main__":
    unittest.main()

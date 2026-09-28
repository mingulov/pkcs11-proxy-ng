"""Stage C (Task 5b) publication/release/staging workflow tests.

RED-FIRST: these tests describe the required guarded production
publication path (``.github/workflows/publish.yml``), the main-only
staging path (``.github/workflows/publish-staging.yml``), the
registry-source release path (``.github/workflows/release.yml``), and
the candidate-evidence helper (``scripts/release/package_evidence.py``
via new ``release_checks.py`` subcommands). They fail until those
workflows and helpers exist with the exact guarded behavior below.

Conventions follow Stage B's ``test_publish_workflows.py``: YAML
structure assertions plus behavior tests of the shared CLI with
controlled fixtures. No real GitHub writes, uploads, tags, or network.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - test env provides PyYAML
    yaml = None

ROOT = Path(__file__).resolve().parents[2]
PUBLISH_YML = ROOT / ".github" / "workflows" / "publish.yml"
STAGING_YML = ROOT / ".github" / "workflows" / "publish-staging.yml"
RELEASE_YML = ROOT / ".github" / "workflows" / "release.yml"
CHECKLIST = ROOT / "doc" / "release" / "0.x-beta-release-checklist.md"
GUIDE = ROOT / "doc" / "release" / "crates-io-publishing.md"
SCRIPTS_README = ROOT / "scripts" / "README.md"

RELEASE_RUST = "1.98.1"
MSRV = "1.88.0"
PROTOC = "36.1"
OIDC_AUTH_PIN = "c6f97d42243bad5fab37ca0427f495c86d5b1a18"
BOOTSTRAP_TOKEN = "CARGO_REGISTRY_BOOTSTRAP_TOKEN"
STAGING_TOKEN = "CARGO_REGISTRIES_STAGING_TOKEN"
PUBLISH_WORKFLOW_PATH = ".github/workflows/publish.yml"

sys.path.insert(0, str(ROOT / "scripts"))
import release_checks  # noqa: E402


def load_workflow(path):
    if yaml is None:
        raise unittest.SkipTest("PyYAML is required to parse workflows")
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def workflow_triggers(workflow):
    # YAML 1.1 parses the `on:` key as boolean True; accept either form.
    triggers = workflow.get("on", workflow.get(True, {}))
    return triggers if isinstance(triggers, dict) else {}


def job_text(job_id, workflow):
    return yaml.safe_dump(workflow["jobs"][job_id], default_flow_style=False)


def run_blocks(job):
    return [step.get("run", "") for step in job.get("steps", [])
            if isinstance(step, dict) and "run" in step]


def step_names(job):
    return [step.get("name", "") for step in job.get("steps", [])
            if isinstance(step, dict)]


class PublishTriggerTests(unittest.TestCase):
    def test_publish_workflow_exists_with_manual_dispatch(self):
        workflow = load_workflow(PUBLISH_YML)
        triggers = workflow_triggers(workflow)
        self.assertIn("workflow_dispatch", triggers)

    def test_mode_defaults_to_dry_run_with_three_options(self):
        workflow = load_workflow(PUBLISH_YML)
        inputs = workflow_triggers(workflow)["workflow_dispatch"].get("inputs", {})
        self.assertEqual(inputs["mode"]["default"], "dry-run")
        self.assertEqual(sorted(inputs["mode"]["options"]),
                         ["bootstrap", "dry-run", "trusted"])

    def test_package_defaults_to_workspace(self):
        workflow = load_workflow(PUBLISH_YML)
        inputs = workflow_triggers(workflow)["workflow_dispatch"].get("inputs", {})
        self.assertEqual(inputs["package"]["default"], "workspace")

    def test_tag_push_validates_only(self):
        """A tag push runs validation, never the upload job."""
        workflow = load_workflow(PUBLISH_YML)
        triggers = workflow_triggers(workflow)
        self.assertIn("push", triggers)
        self.assertIn("tags", triggers["push"])
        upload_if = workflow["jobs"]["upload"].get("if", "")
        self.assertIn("workflow_dispatch", upload_if)
        self.assertIn("dry-run", upload_if)


class PublishJobBoundaryTests(unittest.TestCase):
    def test_required_jobs_exist(self):
        workflow = load_workflow(PUBLISH_YML)
        jobs = workflow["jobs"]
        for job_id in ("preflight", "candidate", "upload",
                       "verify", "dispatch-release"):
            with self.subTest(job=job_id):
                self.assertIn(job_id, jobs)

    def test_no_reusable_workflow_calls(self):
        # Reusable calls never schedule here (repeated startup_failure
        # with zero jobs); the CI gate and the release handoff use the
        # check-runs API and gh dispatch instead.
        workflow = load_workflow(PUBLISH_YML)
        for job_id, job in workflow["jobs"].items():
            with self.subTest(job=job_id):
                self.assertNotIn("./.github/workflows",
                                 str(job.get("uses", "")))

    def test_preflight_requires_green_ci_aggregate(self):
        workflow = load_workflow(PUBLISH_YML)
        job = workflow["jobs"]["preflight"]
        runs = "\n".join(run_blocks(job))
        self.assertIn("check-runs", runs)
        self.assertIn("CI success (fail-closed aggregate)", runs)
        permissions = job.get("permissions", {})
        self.assertEqual(permissions.get("checks"), "read")

    def test_protected_upload_gating(self):
        workflow = load_workflow(PUBLISH_YML)
        upload = workflow["jobs"]["upload"]
        self.assertEqual(upload.get("environment"), "crates-io")
        self.assertIn("needs", upload)
        for needed in ("preflight", "candidate"):
            self.assertIn(needed, upload["needs"])

    def test_oidc_write_scoped_to_upload_job_only(self):
        workflow = load_workflow(PUBLISH_YML)
        scoped = [job_id for job_id, job in workflow["jobs"].items()
                  if job.get("permissions", {}).get("id-token") == "write"]
        self.assertEqual(scoped, ["upload"])

    def test_upload_job_compiles_nothing(self):
        """Compilation in the OIDC-capable job is NOT isolation."""
        workflow = load_workflow(PUBLISH_YML)
        runs = "\n".join(run_blocks(workflow["jobs"]["upload"]))
        for command in ("cargo build", "cargo test", "cargo check",
                        "cargo clippy", "cargo doc"):
            with self.subTest(command=command):
                self.assertNotIn(command, runs)
        for line in runs.splitlines():
            if "cargo package" in line or "cargo publish" in line:
                with self.subTest(line=line):
                    self.assertIn("--no-verify", line)

    def test_repackage_copies_from_isolated_target_dir(self):
        """C1: cargo package honors CARGO_TARGET_DIR, so the copy must."""
        workflow = load_workflow(PUBLISH_YML)
        runs = "\n".join(run_blocks(workflow["jobs"]["upload"]))
        self.assertIn("$CARGO_TARGET_DIR/package/", runs)
        self.assertNotIn("cp target/package/", runs)

    def test_credential_steps_follow_guards(self):
        workflow = load_workflow(PUBLISH_YML)
        names = step_names(workflow["jobs"]["upload"])
        blob = "\n".join(names).lower()
        first_guard = min(blob.index(needle) for needle in
                          ("subject", "receipt", "preflight", "compare"))
        auth_index = blob.index("authenticate")
        publish_index = blob.index("publish bounded")
        self.assertLess(first_guard, auth_index)
        self.assertLess(auth_index, publish_index)

    def test_production_concurrency_is_non_cancelling(self):
        workflow = load_workflow(PUBLISH_YML)
        concurrency = workflow["jobs"]["upload"].get("concurrency", {})
        self.assertFalse(concurrency.get("cancel-in-progress", True))
        self.assertIn("publish", concurrency.get("group", ""))

    def test_user_selections_not_interpolated_into_shell(self):
        workflow = load_workflow(PUBLISH_YML)
        for job_id, job in workflow["jobs"].items():
            for block in run_blocks(job):
                with self.subTest(job=job_id):
                    self.assertNotIn("${{ inputs.", block)
                    self.assertNotIn("github.event.inputs", block)

    def test_real_jobs_have_timeouts(self):
        workflow = load_workflow(PUBLISH_YML)
        for job_id, job in workflow["jobs"].items():
            if "uses" in job:
                continue  # reusable-call schema governs timeouts
            with self.subTest(job=job_id):
                self.assertIn("timeout-minutes", job)


class PublishEvidenceTests(unittest.TestCase):
    def test_pre_auth_artifact_is_immutable_and_retained(self):
        workflow = load_workflow(PUBLISH_YML)
        text = job_text("candidate", workflow)
        self.assertIn("crates-candidate-", text)
        self.assertIn("run_id", text)
        self.assertIn("overwrite: false", text)
        self.assertIn("retention-days: 90", text)

    def test_pre_auth_artifact_carries_all_eight_plus_binding(self):
        workflow = load_workflow(PUBLISH_YML)
        text = job_text("candidate", workflow)
        self.assertIn("SHA256SUMS", text)
        self.assertIn("inventory", text)
        self.assertIn("qualification", text)
        self.assertIn("source_commit", text)

    def test_trusted_auth_uses_pinned_official_action(self):
        workflow = load_workflow(PUBLISH_YML)
        text = job_text("upload", workflow)
        self.assertIn(f"rust-lang/crates-io-auth-action@{OIDC_AUTH_PIN}", text)

    def test_bootstrap_token_name(self):
        workflow = load_workflow(PUBLISH_YML)
        self.assertIn(BOOTSTRAP_TOKEN, job_text("upload", workflow))

    def test_no_credentials_in_logged_artifacts(self):
        workflow = load_workflow(PUBLISH_YML)
        text = job_text("upload", workflow)
        self.assertNotIn("::add-mask", text)
        for block in run_blocks(workflow["jobs"]["upload"]):
            self.assertNotIn("echo $CARGO_REGISTRY", block)
            self.assertNotIn("echo ${CARGO_REGISTRY", block)

    def test_post_upload_verify_is_read_only(self):
        workflow = load_workflow(PUBLISH_YML)
        job = workflow["jobs"]["verify"]
        self.assertNotIn("environment", job)
        text = job_text("verify", workflow)
        self.assertIn("registry-verify", text)
        self.assertIn("registry-consumer", text)

    def test_release_dispatched_only_on_explicit_complete_success(self):
        workflow = load_workflow(PUBLISH_YML)
        job = workflow["jobs"]["dispatch-release"]
        self.assertIn("complete", job.get("if", ""))
        self.assertIn("verify", job.get("needs", []))
        self.assertIn("preflight", job.get("needs", []))
        runs = "\n".join(run_blocks(job))
        self.assertIn("gh workflow run release.yml", runs)
        self.assertIn("--ref", runs)
        self.assertIn('-R "${{ github.repository }}"', runs)
        for flag in ("tag=", "candidate_run_id=",
                     "qualification-url=", "qualification-subject="):
            with self.subTest(flag=flag):
                self.assertIn(flag, runs)
        permissions = job.get("permissions", {})
        self.assertEqual(permissions.get("actions"), "write")
        self.assertNotEqual(permissions.get("id-token"), "write")

    def test_individual_recovery_prints_full_follow_up_command(self):
        workflow = load_workflow(PUBLISH_YML)
        text = job_text("upload", workflow)
        self.assertIn("gh workflow run", text)
        self.assertIn("publish.yml", text)

    def test_publish_order_matches_dependency_order(self):
        from release.package_model import PACKAGES
        workflow = load_workflow(PUBLISH_YML)
        order = workflow["jobs"]["upload"]["env"]["PUBLISH_ORDER"]
        self.assertEqual(order.split(), [name for name, _ in PACKAGES])


class PublishCandidateResolutionTests(unittest.TestCase):
    """The candidate job must consume the CI-built archives from the
    green CI run on the tag, not from its own run.

    Reusable calls never schedule here, so CI and publish are always
    separate runs: downloading ``ci-candidate-<own sha>-<own run id>``
    fails with "artifact not found". The job resolves the newest
    completed green CI run on the tag commit, downloads that exact
    artifact cross-run, and the existing source_commit binding check
    pins it to the tag commit.
    """

    def download_step(self):
        workflow = load_workflow(PUBLISH_YML)
        steps = workflow["jobs"]["candidate"]["steps"]
        matches = [step for step in steps
                   if step.get("name") == "Download CI candidate archives"]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_candidate_resolves_newest_green_ci_run(self):
        workflow = load_workflow(PUBLISH_YML)
        runs = "\n".join(run_blocks(workflow["jobs"]["candidate"]))
        self.assertIn("actions/workflows/ci.yml/runs", runs)
        self.assertIn('conclusion == "success"', runs)
        self.assertIn("head_sha", runs)
        self.assertIn("refusing", runs)

    def test_candidate_download_uses_resolved_run_not_own(self):
        step = self.download_step()
        with_block = step.get("with", {})
        self.assertIn("run-id", with_block)
        self.assertIn("resolve-ci", str(with_block))
        name = str(with_block.get("name", ""))
        self.assertNotIn("github.run_id", name)
        self.assertNotIn("github.sha", name)
        self.assertIn("ci-candidate-", name)

    def test_candidate_download_passes_token_for_cross_run(self):
        step = self.download_step()
        with_block = step.get("with", {})
        self.assertIn("GITHUB_TOKEN", str(with_block.get("github-token", "")))

    def test_artifact_chain_holds_actions_permissions(self):
        # Top-level permissions are contents:read only, so every job
        # touching artifacts needs its own actions scope: candidate
        # downloads cross-run and uploads the immutable artifact,
        # upload downloads the pre-auth set and retains evidence,
        # verify downloads the pre-auth set read-only.
        workflow = load_workflow(PUBLISH_YML)
        candidate = workflow["jobs"]["candidate"].get("permissions", {})
        self.assertEqual(candidate.get("contents"), "read")
        self.assertEqual(candidate.get("actions"), "write")
        upload = workflow["jobs"]["upload"].get("permissions", {})
        self.assertEqual(upload.get("id-token"), "write")
        self.assertEqual(upload.get("actions"), "write")
        verify = workflow["jobs"]["verify"].get("permissions", {})
        self.assertEqual(verify.get("contents"), "read")
        self.assertEqual(verify.get("actions"), "read")


class ReleaseTriggerTests(unittest.TestCase):
    def test_release_is_reusable_plus_manual_retry(self):
        workflow = load_workflow(RELEASE_YML)
        triggers = workflow_triggers(workflow)
        self.assertIn("workflow_call", triggers)
        self.assertIn("workflow_dispatch", triggers)
        inputs = triggers["workflow_dispatch"].get("inputs", {})
        for name in ("tag", "candidate_run_id", "qualification-url",
                     "qualification-subject"):
            with self.subTest(input=name):
                self.assertIn(name, inputs)

    def test_no_tag_push_workspace_builds(self):
        workflow = load_workflow(RELEASE_YML)
        triggers = workflow_triggers(workflow)
        self.assertNotIn("push", triggers)
        text = RELEASE_YML.read_text(encoding="utf-8")
        self.assertNotIn("release-dry-run.sh", text)
        self.assertNotIn("release-windows.sh", text)
        self.assertNotIn("target/release/", text)

    def test_sc2034_unused_version_fixed(self):
        import re
        workflow = load_workflow(RELEASE_YML)
        for job_id, job in workflow["jobs"].items():
            for block in run_blocks(job):
                assigned = re.findall(r"(?m)^\s*VERSION=", block)
                used = re.search(r"\$VERSION|\$\{VERSION", block)
                with self.subTest(job=job_id):
                    if assigned:
                        self.assertIsNotNone(
                            used, f"VERSION assigned but unused in {job_id}")


class ReleaseRecoveryTests(unittest.TestCase):
    def test_recovery_validates_run_identity(self):
        workflow = load_workflow(RELEASE_YML)
        text = job_text("recover", workflow)
        self.assertIn(PUBLISH_WORKFLOW_PATH, text)
        self.assertIn("workflow_dispatch", text)
        self.assertIn("head_sha", text)
        self.assertIn("candidate_run_id", text)

    def test_recovery_permissions_are_read_only(self):
        workflow = load_workflow(RELEASE_YML)
        permissions = workflow["jobs"]["recover"].get("permissions", {})
        self.assertEqual(permissions.get("actions"), "read")
        self.assertIn(permissions.get("contents"), (None, "read"))
        for scope, access in permissions.items():
            with self.subTest(scope=scope):
                self.assertNotEqual(access, "write")

    def test_recovery_rechecks_source_and_binding(self):
        workflow = load_workflow(RELEASE_YML)
        text = job_text("recover", workflow)
        for needle in ("verify-release-subject.sh", "verify-quality-receipt.sh",
                       "preflight", "evidence-verify", "tag-evidence"):
            with self.subTest(needle=needle):
                self.assertIn(needle, text)

    def test_registry_rechecked_before_binaries(self):
        workflow = load_workflow(RELEASE_YML)
        jobs = workflow["jobs"]
        self.assertIn("registry-recheck", jobs)
        text = job_text("registry-recheck", workflow)
        self.assertIn("registry-verify", text)
        self.assertIn("registry-consumer", text)
        for job_id in ("binary-linux", "binary-windows"):
            with self.subTest(job=job_id):
                self.assertIn("registry-recheck", jobs[job_id]["needs"])

    def test_binary_jobs_use_registry_source_only(self):
        workflow = load_workflow(RELEASE_YML)
        for job_id in ("binary-linux", "binary-windows"):
            # Assert on raw run text: safe_dump re-wraps long scalars.
            runs = "\n".join(run_blocks(workflow["jobs"][job_id]))
            with self.subTest(job=job_id):
                self.assertIn("--source registry", runs)
                self.assertNotIn("--source archive", runs)
                self.assertIn("notices", runs)
                self.assertIn("bundle", runs)

    def test_binary_jobs_have_no_registry_token_or_oidc(self):
        workflow = load_workflow(RELEASE_YML)
        for job_id in ("binary-linux", "binary-windows"):
            job = workflow["jobs"][job_id]
            permissions = job.get("permissions", {})
            text = job_text(job_id, workflow)
            with self.subTest(job=job_id):
                self.assertNotEqual(permissions.get("id-token"), "write")
                self.assertNotIn("CARGO_REGISTRY", text)
                self.assertNotIn("crates-io-auth-action", text)

    def test_native_smokes_run_before_publication(self):
        workflow = load_workflow(RELEASE_YML)
        jobs = workflow["jobs"]
        for job_id in ("smoke-linux", "smoke-windows"):
            with self.subTest(job=job_id):
                self.assertIn(job_id, jobs)
        text = job_text("smoke-linux", workflow)
        self.assertIn("ci-package-smoke.py", text)
        self.assertIn("linux-bundle", text)
        self.assertIn("windows-bundle", job_text("smoke-windows", workflow))
        publish_needs = jobs["publish"].get("needs", [])
        self.assertIn("smoke-linux", publish_needs)
        self.assertIn("smoke-windows", publish_needs)

    def test_user_selections_not_interpolated_into_shell(self):
        workflow = load_workflow(RELEASE_YML)
        for job_id, job in workflow["jobs"].items():
            for block in run_blocks(job):
                with self.subTest(job=job_id):
                    self.assertNotIn("${{ inputs.", block)
                    self.assertNotIn("github.event.inputs", block)

    def test_real_jobs_have_timeouts(self):
        workflow = load_workflow(RELEASE_YML)
        for job_id, job in workflow["jobs"].items():
            if "uses" in job:
                continue
            with self.subTest(job=job_id):
                self.assertIn("timeout-minutes", job)


class ReleasePublicationTests(unittest.TestCase):
    def test_final_publication_is_protected_write_only(self):
        workflow = load_workflow(RELEASE_YML)
        job = workflow["jobs"]["publish"]
        self.assertEqual(job.get("environment"), "release")
        self.assertEqual(job.get("permissions", {}).get("contents"), "write")
        writers = [job_id for job_id, other in workflow["jobs"].items()
                   if other.get("permissions", {}).get("contents") == "write"]
        self.assertEqual(writers, ["publish"])

    def test_single_combined_asset_path_with_exact_tag(self):
        workflow = load_workflow(RELEASE_YML)
        text = job_text("publish", workflow)
        self.assertEqual(text.count("action-gh-release@"), 1)
        self.assertIn("tag_name", text)

    def test_divergent_assets_refuse_before_write(self):
        workflow = load_workflow(RELEASE_YML)
        text = job_text("publish", workflow)
        self.assertIn("assets-compare", text)
        self.assertLess(text.index("assets-compare"),
                        text.index("action-gh-release@"))

    def test_all_retained_retry_uploads_nothing(self):
        workflow = load_workflow(RELEASE_YML)
        text = job_text("publish", workflow)
        self.assertIn("add_count", text)

    def test_never_moves_tags_or_deletes_assets(self):
        text = RELEASE_YML.read_text(encoding="utf-8")
        self.assertNotIn("git tag -f", text)
        self.assertNotIn("git push --force", text)
        self.assertNotIn("delete-release", text)
        self.assertNotIn("allowUpdates: true", text)


class StagingWorkflowTests(unittest.TestCase):
    def test_staging_is_manual_main_only(self):
        workflow = load_workflow(STAGING_YML)
        triggers = workflow_triggers(workflow)
        self.assertIn("workflow_dispatch", triggers)
        self.assertNotIn("push", triggers)
        text = STAGING_YML.read_text(encoding="utf-8")
        self.assertIn("refs/heads/main", text)

    def test_staging_uses_own_environment_and_token(self):
        load_workflow(STAGING_YML)
        text = STAGING_YML.read_text(encoding="utf-8")
        self.assertIn("crates-io-staging", text)
        self.assertIn(STAGING_TOKEN, text)
        self.assertNotIn(BOOTSTRAP_TOKEN, text)

    def test_staging_token_scoped_to_upload_steps_only(self):
        """M1: the staging secret must not leak into every job step."""
        workflow = load_workflow(STAGING_YML)
        job = workflow["jobs"]["staging-upload"]
        self.assertNotIn(STAGING_TOKEN, job.get("env", {}))
        steps = {step.get("name"): step for step in job.get("steps", [])}
        for name in ("Dry-run staging publish (endpoint validation)",
                     "Publish probe to staging registry"):
            with self.subTest(step=name):
                self.assertIn(STAGING_TOKEN, steps[name].get("env", {}))

    def test_probe_job_needs_no_toolchain(self):
        """M3: probe generation is pure Python; no toolchain/protoc."""
        workflow = load_workflow(STAGING_YML)
        text = job_text("probe", workflow)
        self.assertNotIn("rust-toolchain", text)
        self.assertNotIn("setup-protoc", text)
        self.assertNotIn("CARGO_TARGET_DIR", text)

    def test_dry_run_precedes_real_upload(self):
        workflow = load_workflow(STAGING_YML)
        names = step_names(workflow["jobs"]["staging-upload"])
        dry = names.index("Dry-run staging publish (endpoint validation)")
        real = names.index("Publish probe to staging registry")
        self.assertLess(dry, real)

    def test_endpoint_binding_validated_before_credentials(self):
        workflow = load_workflow(STAGING_YML)
        text = job_text("staging-upload", workflow)
        self.assertIn("STAGING_OIDC_URL", text)
        self.assertIn("https://", text)

    def test_both_staging_jobs_gate_on_main(self):
        workflow = load_workflow(STAGING_YML)
        for job_id in ("probe", "staging-upload"):
            with self.subTest(job=job_id):
                self.assertIn("refs/heads/main",
                              workflow["jobs"][job_id].get("if", ""))

    def test_staging_builds_dependency_free_probe_first(self):
        workflow = load_workflow(STAGING_YML)
        jobs = workflow["jobs"]
        self.assertIn("probe", jobs)
        self.assertIn("staging-probe", job_text("probe", workflow))
        upload_needs = workflow["jobs"]["staging-upload"].get("needs", [])
        self.assertIn("probe", upload_needs)

    def test_staging_never_touches_production_registry(self):
        text = STAGING_YML.read_text(encoding="utf-8")
        self.assertNotIn("--registry crates-io", text)
        self.assertNotIn("crates-io-auth-action", text)

    def test_real_jobs_have_timeouts(self):
        workflow = load_workflow(STAGING_YML)
        for job_id, job in workflow["jobs"].items():
            if "uses" in job:
                continue
            with self.subTest(job=job_id):
                self.assertIn("timeout-minutes", job)


CARGO_RUNNING_JOBS = {
    PUBLISH_YML: ("upload", "verify"),
    STAGING_YML: ("staging-upload",),
    RELEASE_YML: ("registry-recheck", "binary-linux", "binary-windows"),
}


class WorkflowPinTests(unittest.TestCase):
    def test_toolchain_and_protoc_pins(self):
        for path in (PUBLISH_YML, STAGING_YML, RELEASE_YML):
            text = Path(path).read_text(encoding="utf-8")
            with self.subTest(path=str(path)):
                self.assertIn(RELEASE_RUST, text)
                self.assertIn(PROTOC, text)
                self.assertNotIn("toolchain: stable", text)
        for path in (PUBLISH_YML, RELEASE_YML):
            text = Path(path).read_text(encoding="utf-8")
            with self.subTest(path=str(path)):
                self.assertIn(MSRV, text)

    def test_cargo_dirs_isolated_in_every_cargo_running_job(self):
        for path, jobs in CARGO_RUNNING_JOBS.items():
            workflow = load_workflow(path)
            for job_id in jobs:
                with self.subTest(path=str(path), job=job_id):
                    text = job_text(job_id, workflow)
                    self.assertIn("CARGO_TARGET_DIR", text)
                    self.assertIn("CARGO_BUILD_BUILD_DIR", text)


TAG_COMMIT = "6b151b799b59bce4a06f6cb993f8a74a84ae0481"
RUN_ID = "12345678"
QUAL_URL = "https://example.invalid/qual/rec-42"
QUAL_SUBJECT = "abc123def456abc123def456abc123def456abcd"


class CandidateEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workdir = Path(self.temp.name)

    def test_candidate_name_is_exact(self):
        import io
        from contextlib import redirect_stdout
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = release_checks.main(
                ["candidate-name", "--tag-commit", TAG_COMMIT,
                 "--run-id", RUN_ID], repo=ROOT)
        self.assertEqual(code, 0)
        self.assertEqual(buffer.getvalue().strip(),
                         f"crates-candidate-{TAG_COMMIT}-{RUN_ID}")

    def test_candidate_name_refuses_malformed_inputs(self):
        for args in (["--tag-commit", "short", "--run-id", RUN_ID],
                     ["--tag-commit", TAG_COMMIT, "--run-id", "0"],
                     ["--tag-commit", TAG_COMMIT, "--run-id", "abc"],
                     ["--tag-commit", "X" * 40, "--run-id", RUN_ID]):
            with self.subTest(args=args):
                self.assertEqual(
                    release_checks.main(["candidate-name", *args], repo=ROOT), 1)

    def write_binding(self, **overrides):
        binding = self.workdir / "binding.json"
        args = ["evidence-bind", "--output", str(binding),
                "--tag-commit", TAG_COMMIT, "--run-id", RUN_ID,
                "--qualification-url", QUAL_URL,
                "--qualification-subject", QUAL_SUBJECT]
        for key, value in overrides.items():
            flag = "--" + key.replace("_", "-")
            index = args.index(flag)
            args[index + 1] = value
        self.assertEqual(release_checks.main(args, repo=ROOT), 0)
        return binding

    def test_evidence_bind_writes_exact_binding(self):
        binding = self.write_binding()
        payload = json.loads(binding.read_text(encoding="utf-8"))
        self.assertEqual(payload["tag_commit"], TAG_COMMIT)
        self.assertEqual(payload["run_id"], RUN_ID)
        self.assertEqual(payload["qualification_url"], QUAL_URL)
        self.assertEqual(payload["qualification_subject"], QUAL_SUBJECT)

    def test_evidence_bind_refuses_non_https_url(self):
        binding = self.workdir / "binding.json"
        code = release_checks.main(
            ["evidence-bind", "--output", str(binding),
             "--tag-commit", TAG_COMMIT, "--run-id", RUN_ID,
             "--qualification-url", "http://example.invalid/qual",
             "--qualification-subject", QUAL_SUBJECT], repo=ROOT)
        self.assertEqual(code, 1)
        self.assertFalse(binding.exists())

    def verify(self, binding, **overrides):
        args = ["evidence-verify", "--binding", str(binding),
                "--expect-url", QUAL_URL, "--expect-subject", QUAL_SUBJECT,
                "--expect-tag-commit", TAG_COMMIT,
                "--expect-run-id", RUN_ID]
        for key, value in overrides.items():
            flag = "--" + key.replace("_", "-")
            index = args.index(flag)
            args[index + 1] = value
        return release_checks.main(args, repo=ROOT)

    def test_evidence_verify_accepts_exact_binding(self):
        self.assertEqual(self.verify(self.write_binding()), 0)

    def test_evidence_verify_refuses_wrong_binding(self):
        binding = self.write_binding()
        cases = ({"expect_url": QUAL_URL + "/other"},
                 {"expect_subject": "0" * 40},
                 {"expect_tag_commit": "0" * 40},
                 {"expect_run_id": "999"})
        for overrides in cases:
            with self.subTest(overrides=overrides):
                self.assertEqual(self.verify(binding, **overrides), 1)

    def test_evidence_verify_refuses_missing_or_malformed(self):
        missing = self.workdir / "absent.json"
        self.assertEqual(self.verify(missing), 1)
        broken = self.workdir / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        self.assertEqual(self.verify(broken), 1)


def run_record(**overrides):
    record = {"id": int(RUN_ID),
              "repository": "example/pkcs11-proxy-ng",
              "workflow_path": PUBLISH_WORKFLOW_PATH,
              "event": "workflow_dispatch",
              "head_sha": TAG_COMMIT,
              "artifacts": [{"name": f"crates-candidate-{TAG_COMMIT}-{RUN_ID}",
                             "expired": False,
                             "expires_at": "2031-01-01T00:00:00Z"}]}
    record.update(overrides)
    return record


class EvidenceSelectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workdir = Path(self.temp.name)

    def select(self, runs, **overrides):
        path = self.workdir / "runs.json"
        path.write_text(json.dumps({"runs": runs}), encoding="utf-8")
        args = ["evidence-select", "--runs-json", str(path),
                "--run-id", RUN_ID,
                "--repository", "example/pkcs11-proxy-ng",
                "--workflow", PUBLISH_WORKFLOW_PATH,
                "--event", "workflow_dispatch",
                "--head-sha", TAG_COMMIT,
                "--name", f"crates-candidate-{TAG_COMMIT}-{RUN_ID}"]
        for key, value in overrides.items():
            flag = "--" + key.replace("_", "-")
            index = args.index(flag)
            args[index + 1] = value
        return release_checks.main(args, repo=ROOT)

    def test_selects_exact_one_match(self):
        self.assertEqual(self.select([run_record()]), 0)

    def test_refuses_wrong_run_identity(self):
        base = [run_record()]
        for overrides in ({"repository": "example/other"},
                          {"workflow": ".github/workflows/ci.yml"},
                          {"event": "push"},
                          {"head_sha": "0" * 40},
                          {"run_id": "999"},
                          {"name": "other-artifact"}):
            with self.subTest(overrides=overrides):
                self.assertEqual(self.select(base, **overrides), 1)

    def test_refuses_expired_evidence(self):
        record = run_record()
        record["artifacts"][0]["expired"] = True
        self.assertEqual(self.select([record]), 1)
        record = run_record()
        record["artifacts"][0]["expires_at"] = "2020-01-01T00:00:00Z"
        self.assertEqual(self.select([record]), 1)

    def test_refuses_ambiguous_evidence(self):
        record = run_record()
        record["artifacts"].append(dict(record["artifacts"][0]))
        self.assertEqual(self.select([record]), 1)

    def test_refuses_missing_runs_file(self):
        path = self.workdir / "absent.json"
        code = release_checks.main(
            ["evidence-select", "--runs-json", str(path),
             "--run-id", RUN_ID, "--repository", "example/pkcs11-proxy-ng",
             "--workflow", PUBLISH_WORKFLOW_PATH, "--event",
             "workflow_dispatch", "--head-sha", TAG_COMMIT,
             "--name", "x"], repo=ROOT)
        self.assertEqual(code, 1)


class AssetCompareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workdir = Path(self.temp.name)

    def compare(self, existing, prepared):
        existing_path = self.workdir / "existing.json"
        prepared_path = self.workdir / "prepared.json"
        existing_path.write_text(json.dumps(existing), encoding="utf-8")
        prepared_path.write_text(json.dumps(prepared), encoding="utf-8")
        return release_checks.main(
            ["assets-compare", "--existing-json", str(existing_path),
             "--prepared-json", str(prepared_path)], repo=ROOT)

    def test_identical_assets_retained_and_missing_added(self):
        existing = [{"name": "a.tar.gz", "sha256": "1" * 64}]
        prepared = [{"name": "a.tar.gz", "sha256": "1" * 64,
                     "path": "dist/a.tar.gz"},
                    {"name": "b.zip", "sha256": "2" * 64,
                     "path": "dist/b.zip"}]
        self.assertEqual(self.compare(existing, prepared), 0)

    def test_empty_release_accepts_all_prepared(self):
        prepared = [{"name": "a.tar.gz", "sha256": "1" * 64,
                     "path": "dist/a.tar.gz"}]
        self.assertEqual(self.compare([], prepared), 0)

    def test_divergent_bytes_refuse(self):
        existing = [{"name": "a.tar.gz", "sha256": "1" * 64}]
        prepared = [{"name": "a.tar.gz", "sha256": "2" * 64,
                     "path": "dist/a.tar.gz"}]
        self.assertEqual(self.compare(existing, prepared), 1)

    def test_duplicate_names_refuse(self):
        one = {"name": "a.tar.gz", "sha256": "1" * 64, "path": "dist/a.tar.gz"}
        self.assertEqual(self.compare([], [one, dict(one)]), 1)


class TagEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")
        (self.repo / "file.txt").write_text("x", encoding="utf-8")
        self.git("add", "file.txt")
        self.git("commit", "-qm", "one")

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.repo, check=True,
                       capture_output=True, text=True)

    def check(self, *args):
        return release_checks.main(["tag-evidence", *args], repo=ROOT)

    def test_annotated_tag_reports_object_and_peeled_commit(self):
        self.git("tag", "-a", "v0.2.0", "-m", "release")
        self.assertEqual(self.check("--tag", "v0.2.0",
                                    "--repo", str(self.repo)), 0)

    def test_lightweight_tag_refuses(self):
        self.git("tag", "v0.2.0")
        self.assertEqual(self.check("--tag", "v0.2.0",
                                    "--repo", str(self.repo)), 1)

    def test_missing_tag_refuses(self):
        self.assertEqual(self.check("--tag", "v9.9.9",
                                    "--repo", str(self.repo)), 1)

    def test_wrong_expected_peeled_commit_refuses(self):
        self.git("tag", "-a", "v0.2.0", "-m", "release")
        self.assertEqual(self.check("--tag", "v0.2.0", "--repo",
                                    str(self.repo), "--expect-peeled",
                                    "0" * 40), 1)


class ReleaseDocsAccuracyTests(unittest.TestCase):
    """Stage D guidance must describe the Stage C machinery exactly.

    The release workflow stages only the two bundles plus the JSON
    evidence files (no SHA256SUMS assets); a dry-run dispatch skips
    ``upload`` and therefore ``verify``; and the CI archive jobs are
    named per platform. Each test below fails on the stale wording.
    """

    def test_checklist_names_actual_release_assets(self):
        text = CHECKLIST.read_text(encoding="utf-8")
        start = text.index("The published release contains")
        item = text[start:text.index("\n\n", start)]
        self.assertIn("`inventory.json`", item)
        self.assertIn("`qualification-binding.json`", item)
        self.assertNotIn("SHA256SUMS", text)

    def test_guide_scopes_dry_run_to_guards_ci_candidate(self):
        text = GUIDE.read_text(encoding="utf-8")
        start = text.index("Full registry-only check without uploading")
        item = text[start:text.index("\n\n", start)]
        self.assertIn("`registry-verify`", item)
        self.assertIn("`registry-consumer`", item)
        self.assertNotIn("dispatch `dry-run`", item)
        self.assertIn("candidate only", item)

    def test_scripts_readme_names_both_archive_jobs(self):
        text = SCRIPTS_README.read_text(encoding="utf-8")
        self.assertIn("`archive-binary-linux`", text)
        self.assertIn("`archive-binary-windows`", text)


if __name__ == "__main__":
    unittest.main()

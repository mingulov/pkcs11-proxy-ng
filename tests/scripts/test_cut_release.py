"""Release orchestrator tests (cut-release.yml + write-receipt helper).

RED-FIRST: these tests describe the GUI-dispatched release pipeline:
verify the eight receipt gates plus subject/version/CHANGELOG/tag
preconditions on main, cut an approval-gated receipt-only commit with
an annotated tag, then dispatch publish.yml with the inputs passed
through once. They fail until the workflow and the helper exist.
"""

from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - test env provides PyYAML
    yaml = None

ROOT = Path(__file__).resolve().parents[2]
CUT_YML = ROOT / ".github" / "workflows" / "cut-release.yml"

RELEASE_TAG_ENV = "release-tag"
RELEASE_RUST = "1.98.1"
MSRV = "1.88.0"
PROTOC = "36.1"
AUDIT_VERSION = "0.22.2"
DENY_VERSION = "0.20.2"
GATES = ("fmt", "check", "test", "clippy", "msrv", "audit", "deny",
         "release_dry_run")

sys.path.insert(0, str(ROOT / "scripts"))
import release_checks  # noqa: E402


def load_workflow():
    if yaml is None:
        raise unittest.SkipTest("PyYAML is required to parse workflows")
    return yaml.safe_load(CUT_YML.read_text(encoding="utf-8"))


def workflow_triggers(workflow):
    # YAML 1.1 parses the `on:` key as boolean True; accept either form.
    triggers = workflow.get("on", workflow.get(True, {}))
    return triggers if isinstance(triggers, dict) else {}


def run_text(job):
    return "\n".join(step.get("run", "") for step in job.get("steps", [])
                     if isinstance(step, dict))


class CutTriggerTests(unittest.TestCase):
    def test_dispatch_only_no_push_or_pr_triggers(self):
        triggers = workflow_triggers(load_workflow())
        self.assertEqual(set(triggers), {"workflow_dispatch"})

    def test_version_input_required(self):
        triggers = workflow_triggers(load_workflow())
        version = triggers["workflow_dispatch"]["inputs"]["version"]
        self.assertTrue(version.get("required"))

    def test_mode_defaults_to_dry_run_with_three_options(self):
        triggers = workflow_triggers(load_workflow())
        mode = triggers["workflow_dispatch"]["inputs"]["mode"]
        self.assertEqual(mode.get("default"), "dry-run")
        self.assertEqual(set(mode.get("options", [])),
                         {"dry-run", "bootstrap", "trusted"})

    def test_package_defaults_to_workspace(self):
        triggers = workflow_triggers(load_workflow())
        package = triggers["workflow_dispatch"]["inputs"]["package"]
        self.assertEqual(package.get("default"), "workspace")

    def test_qualification_inputs_present(self):
        triggers = workflow_triggers(load_workflow())
        inputs = triggers["workflow_dispatch"]["inputs"]
        self.assertIn("qualification-url", inputs)
        self.assertIn("qualification-subject", inputs)


class CutVerifyTests(unittest.TestCase):
    def test_verify_runs_all_eight_gates(self):
        workflow = load_workflow()
        run = run_text(workflow["jobs"]["verify"])
        for marker in ("cargo fmt --all -- --check",
                       "cargo check --workspace --locked --all-targets",
                       "cargo test --workspace --locked",
                       "cargo clippy --workspace --locked --all-targets",
                       "-D warnings",
                       "cargo audit",
                       "cargo deny check",
                       "scripts/release-dry-run.sh"):
            with self.subTest(marker=marker):
                self.assertIn(marker, run)

    def test_verify_pins_toolchains(self):
        workflow = load_workflow()
        text = yaml.safe_dump(workflow["jobs"]["verify"],
                              default_flow_style=False)
        for pin in (RELEASE_RUST, MSRV, PROTOC, AUDIT_VERSION,
                    DENY_VERSION):
            with self.subTest(pin=pin):
                self.assertIn(pin, text)

    def test_verify_checks_changelog_version_and_tag_absence(self):
        workflow = load_workflow()
        run = run_text(workflow["jobs"]["verify"])
        self.assertIn("CHANGELOG.md", run)
        self.assertIn("ls-remote", run)
        self.assertIn("refs/tags/", run)

    def test_verify_emits_sha_and_receipt_artifact(self):
        workflow = load_workflow()
        job = workflow["jobs"]["verify"]
        self.assertIn("verified_sha", job.get("outputs", {}))
        run = run_text(job)
        self.assertIn("write-receipt", run)
        self.assertIn("--subject-sha", run)
        uses = " ".join(step.get("uses", "")
                        for step in job.get("steps", [])
                        if isinstance(step, dict))
        self.assertIn("actions/upload-artifact@", uses)


class CutJobTests(unittest.TestCase):
    def test_cut_needs_verify_under_release_tag_env(self):
        workflow = load_workflow()
        job = workflow["jobs"]["cut"]
        self.assertEqual(job.get("needs"), ["verify"])
        self.assertEqual(job.get("environment"), RELEASE_TAG_ENV)

    def test_cut_rechecks_head_before_push(self):
        workflow = load_workflow()
        run = run_text(workflow["jobs"]["cut"])
        self.assertIn("verified_sha", run)
        self.assertIn("HEAD", run)

    def test_cut_verifies_receipt_before_tag(self):
        workflow = load_workflow()
        steps = workflow["jobs"]["cut"]["steps"]
        names = [str(step.get("name", "")) + "\n" +
                 str(step.get("run", "")) for step in steps
                 if isinstance(step, dict)]
        receipt = [i for i, text in enumerate(names)
                   if "verify-quality-receipt" in text]
        tag = [i for i, text in enumerate(names) if "git tag" in text]
        self.assertEqual(len(receipt), 1)
        self.assertEqual(len(tag), 1)
        self.assertLess(receipt[0], tag[0])

    def test_cut_creates_annotated_tag_without_force(self):
        workflow = load_workflow()
        run = run_text(workflow["jobs"]["cut"])
        self.assertIn("git tag -a", run)
        self.assertIn("pkcs11-proxy-ng", run)
        self.assertNotIn("--force", run)
        self.assertNotIn("-f ", run)

    def test_cut_accepts_new_or_modified_receipt(self):
        # Rule (b) allows the tag commit to add or modify the receipt;
        # anything else in the worktree state still refuses.
        workflow = load_workflow()
        run = run_text(workflow["jobs"]["cut"])
        self.assertIn('"?? $RECEIPT"', run)
        self.assertIn('" M $RECEIPT"', run)

    def test_top_level_permissions_stay_read_only(self):
        workflow = load_workflow()
        permissions = workflow.get("permissions", {})
        self.assertEqual(permissions.get("contents"), "read")
        cut_permissions = workflow["jobs"]["cut"].get("permissions", {})
        self.assertEqual(cut_permissions.get("contents"), "write")

    def test_cut_starts_ci_on_new_tag(self):
        # Token pushes trigger no runs: without this the tag commit
        # would never get the CI aggregate publish requires.
        workflow = load_workflow()
        job = workflow["jobs"]["cut"]
        run = run_text(job)
        self.assertIn("gh workflow run ci.yml", run)
        self.assertIn("--ref", run)
        self.assertIn('-R "${{ github.repository }}"', run)
        permissions = job.get("permissions", {})
        self.assertEqual(permissions.get("actions"), "write")


class DispatchJobTests(unittest.TestCase):
    def test_dispatch_needs_cut_and_passes_inputs_once(self):
        workflow = load_workflow()
        job = workflow["jobs"]["dispatch-publish"]
        self.assertEqual(job.get("needs"), ["cut"])
        run = run_text(job)
        self.assertIn("gh workflow run publish.yml", run)
        self.assertIn("--ref", run)
        # No checkout in this job: gh must resolve the repo explicitly
        # or it dies with "fatal: not a git repository".
        self.assertIn('-R "${{ github.repository }}"', run)
        for flag in ("mode=", "package=", "tag=",
                     "qualification-url=", "qualification-subject="):
            with self.subTest(flag=flag):
                self.assertIn(flag, run)

    def test_dispatch_has_actions_write(self):
        workflow = load_workflow()
        permissions = workflow["jobs"]["dispatch-publish"].get(
            "permissions", {})
        self.assertEqual(permissions.get("actions"), "write")

    def test_dispatch_waits_for_tag_ci_before_publish(self):
        # Publish preflight refuses without the green aggregate, so
        # dispatching before tag CI finishes only produces a spurious
        # failed publish run (v0.2.0/v0.2.1 race). The wait step must
        # run before the dispatch step.
        workflow = load_workflow()
        job = workflow["jobs"]["dispatch-publish"]
        steps = [step for step in job.get("steps", [])
                 if isinstance(step, dict)]
        wait = [i for i, step in enumerate(steps)
                if "wait-on-check-action@" in str(step.get("uses", ""))]
        dispatch = [i for i, step in enumerate(steps)
                    if "gh workflow run publish.yml" in str(step.get("run", ""))]
        self.assertEqual(len(wait), 1)
        self.assertEqual(len(dispatch), 1)
        self.assertLess(wait[0], dispatch[0])

    def test_dispatch_wait_is_pinned_and_success_only(self):
        # Supply-chain pinning plus fail-closed conclusions: a skipped
        # aggregate must refuse, never dispatch.
        workflow = load_workflow()
        job = workflow["jobs"]["dispatch-publish"]
        uses = [str(step.get("uses", "")) for step in job.get("steps", [])
                if isinstance(step, dict)]
        pinned = [entry for entry in uses
                  if "wait-on-check-action@" in entry]
        self.assertEqual(len(pinned), 1)
        self.assertRegex(pinned[0], r"wait-on-check-action@[0-9a-f]{40}$")
        with_args = [step.get("with", {}) for step in job.get("steps", [])
                     if isinstance(step, dict) and
                     "wait-on-check-action@" in str(step.get("uses", ""))]
        config = with_args[0]
        self.assertEqual(config.get("check-name"),
                         "CI success (fail-closed aggregate)")
        self.assertEqual(config.get("allowed-conclusions"), "success")
        self.assertIn("needs.cut.outputs.tag", str(config.get("ref", "")))
        permissions = job.get("permissions", {})
        self.assertEqual(permissions.get("checks"), "read")


class WriteReceiptTests(unittest.TestCase):
    def check(self, *args):
        return release_checks.main(["write-receipt", *args])

    def test_writes_exact_shell_compatible_format(self):
        with tempfile.TemporaryDirectory() as temp:
            output = str(Path(temp) / "v0.2.0-quality-receipt.md")
            self.assertEqual(self.check("--version", "0.2.0",
                                        "--subject-sha", "a" * 40,
                                        "--output", output), 0)
            text = Path(output).read_text(encoding="utf-8")
        subjects = re.findall(r"^subject_sha: ([0-9a-fA-F]+)$", text,
                              re.M)
        self.assertEqual(subjects, ["a" * 40])
        for gate in GATES:
            with self.subTest(gate=gate):
                values = re.findall(r"^%s: (.*)$" % gate, text, re.M)
                self.assertEqual(values, ["pass"])

    def test_refuses_bad_subject_sha(self):
        with tempfile.TemporaryDirectory() as temp:
            output = str(Path(temp) / "receipt.md")
            self.assertNotEqual(self.check("--version", "0.2.0",
                                           "--subject-sha", "xyz",
                                           "--output", output), 0)

    def test_refuses_bad_version(self):
        with tempfile.TemporaryDirectory() as temp:
            output = str(Path(temp) / "receipt.md")
            self.assertNotEqual(self.check("--version", "2.0",
                                           "--subject-sha", "b" * 40,
                                           "--output", output), 0)

    def test_overwrites_stale_receipt_with_fresh_attestation(self):
        # The receipt is a living file on main (rule (b) allows the tag
        # commit to modify it); recording a run replaces stale content
        # outright so old evidence lines can never describe a new run.
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "receipt.md"
            output.write_text("# v0.2.0 quality receipt\n\n"
                              "subject_sha: %s\n\ntest: fail\n"
                              "test_evidence: stale run\n" % ("d" * 40),
                              encoding="utf-8")
            self.assertEqual(self.check("--version", "0.2.0",
                                        "--subject-sha", "c" * 40,
                                        "--output", str(output)), 0)
            text = output.read_text(encoding="utf-8")
        subjects = re.findall(r"^subject_sha: ([0-9a-fA-F]+)$", text,
                              re.M)
        self.assertEqual(subjects, ["c" * 40])
        for gate in GATES:
            with self.subTest(gate=gate):
                values = re.findall(r"^%s: (.*)$" % gate, text, re.M)
                self.assertEqual(values, ["pass"])
        self.assertNotIn("stale run", text)


if __name__ == "__main__":
    unittest.main()

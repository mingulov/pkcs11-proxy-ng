"""Nightly release-path probe workflow tests.

The ``release-path-probe`` job in ``nightly.yml`` exercises the
production uploader end to end against a scratch draft release, then
deletes it, so a broken ``scripts/release-upload.sh`` (or a revoked
token scope) pages nightly instead of release day. These tests pin the
probe's shape: a run-scoped draft tag, the real uploader script, an
asset check, and an always-run cleanup — plus the global invariant
the probe relies on, that no workflow triggers on release events.
"""

from __future__ import annotations

import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - test env provides PyYAML
    yaml = None

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
NIGHTLY_YML = WORKFLOWS / "nightly.yml"


def load_workflow(path):
    if yaml is None:
        raise unittest.SkipTest("PyYAML is required to parse workflows")
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def workflow_triggers(workflow):
    # YAML 1.1 parses the `on:` key as boolean True; accept either
    # form. Returns the raw value — scalar, list, or mapping — so
    # `trigger_names` below can normalize every supported form.
    return workflow.get("on", workflow.get(True, {}))


def trigger_names(triggers):
    # `on:` accepts a scalar, a list, or a mapping; normalize all
    # three so `on: release` and `on: [push, release]` cannot evade
    # a mapping-only check.
    if isinstance(triggers, str):
        return [triggers]
    if isinstance(triggers, list):
        return [str(each) for each in triggers]
    if isinstance(triggers, dict):
        return [str(each) for each in triggers]
    return []


def shell_steps(job):
    # (index, step) for run steps only, keeping each step's own
    # identity: never zip names from all steps against blocks from
    # a subset — action steps would misalign the pairing.
    return [(index, step)
            for index, step in enumerate(job.get("steps", []))
            if isinstance(step, dict) and "run" in step]


def step_names(job):
    return [step.get("name", "") for step in job.get("steps", [])
            if isinstance(step, dict)]


class ReleasePathProbeTests(unittest.TestCase):
    def probe_job(self):
        return load_workflow(NIGHTLY_YML)["jobs"]["release-path-probe"]

    def test_probe_job_has_bounded_runtime(self):
        job = self.probe_job()
        self.assertIn("timeout-minutes", job)

    def test_probe_permissions_are_contents_write_only(self):
        job = self.probe_job()
        permissions = job.get("permissions", {})
        self.assertEqual(permissions.get("contents"), "write")
        for scope, access in permissions.items():
            with self.subTest(scope=scope):
                if scope != "contents":
                    self.assertNotEqual(access, "write")

    def test_probe_tag_is_unique_per_run(self):
        job = self.probe_job()
        tag = job.get("env", {}).get("PROBE_TAG", "")
        # Run- AND attempt-scoped: a "re-run failed jobs" retry
        # shares the run id, so run_id alone would collide with
        # the earlier attempt's tag. The ${{ }} form is required —
        # a literal "github.run_id" string would be constant.
        self.assertRegex(
            tag,
            r"nightly-probe-\$\{{\s*github\.run_id\s*\}\}"
            r"-\$\{{\s*github\.run_attempt\s*\}\}")

    def test_probe_creates_draft_before_upload(self):
        # release-upload.sh only ever creates published releases; the
        # probe pre-creates a draft so a leftover never notifies.
        job = self.probe_job()
        creates = [(index, step) for index, step in shell_steps(job)
                   if "gh release create" in step["run"]]
        uploads = [(index, step) for index, step in shell_steps(job)
                   if "scripts/release-upload.sh" in step["run"]]
        self.assertEqual(len(creates), 1)
        self.assertEqual(len(uploads), 1)
        create_index, create = creates[0]
        self.assertLess(create_index, uploads[0][0])
        # The draft creation must be unconditional: a gate here
        # would let the uploader publish a live release.
        self.assertNotIn("if", create)
        self.assertIn("--draft", create["run"])
        self.assertIn("$PROBE_TAG", create["run"])

    def test_probe_uploads_via_release_upload_script(self):
        job = self.probe_job()
        steps = [step for step in job.get("steps", [])
                 if "scripts/release-upload.sh" in str(step.get("run", ""))]
        self.assertEqual(len(steps), 1)
        env = steps[0].get("env", {})
        for key in ("RELEASE_TAG", "RELEASE_TITLE",
                    "RELEASE_NOTES", "STAGE_DIR"):
            with self.subTest(key=key):
                self.assertIn(key, env)
        self.assertIn("PROBE_TAG", str(env["RELEASE_TAG"]))
        # Bounded retries: a dead endpoint must fail the probe in
        # minutes, not after the production 5x600s budget.
        self.assertLessEqual(int(env.get("UPLOAD_ATTEMPTS", "99")), 3)
        self.assertLessEqual(int(env.get("UPLOAD_WINDOW", "9999")), 300)

    def test_probe_verifies_asset_landed(self):
        # One step must both fetch the release and fail when the
        # asset is absent: scattered substrings could pass with a
        # view in one step and a mere mention in another.
        blocks = [step["run"] for _, step
                  in shell_steps(self.probe_job())
                  if "$PROBE_TAG" in step["run"]]
        checks = [block for block in blocks
                  if "gh release view" in block
                  and "grep" in block
                  and "probe.json" in block]
        self.assertEqual(len(checks), 1)

    def test_probe_deletes_scratch_release_always(self):
        job = self.probe_job()
        steps = [step for step in job.get("steps", [])
                 if isinstance(step, dict)]
        deletes = [step for step in steps
                   if "gh release delete" in str(step.get("run", ""))]
        self.assertEqual(len(deletes), 1)
        delete = deletes[0]
        self.assertEqual(delete.get("if"), "always()")
        # --cleanup-tag fails hard when the draft created no git tag,
        # which would fail a healthy probe: the tag goes only when
        # an existence check proves it is there.
        code = "\n".join(line for line in delete["run"].splitlines()
                         if not line.strip().startswith("#"))
        self.assertNotIn("--cleanup-tag", code)
        self.assertIn("$PROBE_TAG", delete["run"])
        self.assertIn("git/ref/tags/", delete["run"])
        self.assertIn("-X DELETE", delete["run"])
        self.assertEqual(step_names(job)[-1], delete["name"])

    def test_no_workflow_triggers_on_release_events(self):
        # The probe's create/upload/delete cycle is side-effect-free
        # only while no workflow listens for release events.
        paths = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
        self.assertTrue(paths, "expected workflow files")
        for path in paths:
            with self.subTest(workflow=path.name):
                triggers = workflow_triggers(load_workflow(path))
                self.assertNotIn("release", trigger_names(triggers))

    def test_trigger_forms_all_detect_release(self):
        # Mutation pin for the normalizer: scalar, list, and mapping
        # `on:` forms (plus the YAML 1.1 boolean-True key) must all
        # surface a release trigger — a mapping-only check would
        # silently pass the scalar and list forms.
        for triggers in ("release",
                         ["push", "release"],
                         {"release": {"types": ["published"]}},
                         {"push": {}, "release": {}}):
            with self.subTest(triggers=triggers):
                names = trigger_names(workflow_triggers({"on": triggers}))
                self.assertIn("release", names)
        names = trigger_names(workflow_triggers({True: "release"}))
        self.assertIn("release", names)
        for clean in ("push", ["push", "pull_request"], {"push": {}}, {}, None):
            with self.subTest(triggers=clean):
                names = trigger_names(workflow_triggers({"on": clean}))
                self.assertNotIn("release", names)


if __name__ == "__main__":
    unittest.main()

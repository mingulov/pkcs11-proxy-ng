"""Q11 (RO-01) production release-authorization preflight tests.

RED-FIRST: these tests describe the read-only environment-preflight
gate: a helper (``scripts/release/package_environments.py``) that
consumes captured GitHub Environments API JSON and returns a
fail-closed verdict, a ``release_checks.py environments-preflight``
subcommand, one gate step in each pre-mutation release job
(``cut-release.yml`` verify, ``publish.yml`` preflight, ``release.yml``
recover), and the protection-contract doc. They fail until those exist.

Conventions follow ``test_publish_release.py``: YAML structure
assertions plus behavior tests of the shared CLI with controlled
fixtures. No live GitHub calls, uploads, tags, or network.
"""

from __future__ import annotations

import json
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
PUBLISH_YML = ROOT / ".github" / "workflows" / "publish.yml"
RELEASE_YML = ROOT / ".github" / "workflows" / "release.yml"
CONTRACT = ROOT / "doc" / "release" / "environment-protection-contract.md"

PRODUCTION_ENVS = ("release-tag", "crates-io", "release")

sys.path.insert(0, str(ROOT / "scripts"))
import release_checks  # noqa: E402


def load_environments():
    # package_environments.py uses a relative import; load its package.
    package_dir = str(ROOT / "scripts")
    if package_dir not in sys.path:
        sys.path.insert(0, package_dir)
    import release.package_environments as envs

    return envs


def load_workflow(path):
    if yaml is None:
        raise unittest.SkipTest("PyYAML is required to parse workflows")
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def env_entry(name, *, reviewers=True, empty_reviewers=False, policy="custom"):
    """One Environments-API entry in the captured readback shape."""
    rules = [{"id": 11, "node_id": "rule-branch", "type": "branch_policy"}]
    if reviewers:
        rules.append({"id": 12, "node_id": "rule-reviewers",
                      "type": "required_reviewers",
                      "prevent_self_review": False,
                      "reviewers": [] if empty_reviewers else
                      [{"type": "User",
                        "reviewer": {"login": "owner", "id": 1}}]})
    policies = {"custom": {"protected_branches": False,
                           "custom_branch_policies": True},
                "protected": {"protected_branches": True,
                              "custom_branch_policies": False},
                "none": {"protected_branches": False,
                         "custom_branch_policies": False},
                "null": None}
    return {"id": 21, "node_id": "env", "name": name,
            "url": f"https://api.github.com/repos/owner/repo/environments/{name}",
            "html_url": "https://github.com/owner/repo/deployments",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "can_admins_bypass": False,
            "protection_rules": rules,
            "deployment_branch_policy": policies[policy]}


def list_payload(*entries):
    return {"total_count": len(entries), "environments": list(entries)}


def policies_payload(*pairs):
    return {"total_count": len(pairs),
            "branch_policies": [{"id": index, "node_id": "policy",
                                 "name": name, "type": kind}
                                for index, (kind, name) in enumerate(pairs)]}


def protected_list():
    return list_payload(env_entry("release-tag"), env_entry("crates-io"),
                        env_entry("release"))


def intended_policies():
    return {"release-tag": policies_payload(("branch", "main")),
            "crates-io": policies_payload(("tag", "v*")),
            "release": policies_payload(("tag", "v*"))}


class ProtectionContractTests(unittest.TestCase):
    def check(self, payload, policies=None, environments=PRODUCTION_ENVS):
        envs = load_environments()
        return envs.verify_environment_protections(
            payload, policies or intended_policies(), environments)

    def test_all_three_protected_passes(self):
        self.assertEqual(self.check(protected_list()), PRODUCTION_ENVS)

    def test_single_environment_selection_passes(self):
        payload = list_payload(env_entry("crates-io"))
        policies = {"crates-io": policies_payload(("tag", "v*"))}
        self.assertEqual(self.check(payload, policies, ("crates-io",)),
                         ("crates-io",))

    def test_absent_reviewer_rule_refuses(self):
        for name in PRODUCTION_ENVS:
            with self.subTest(environment=name):
                entries = [env_entry(candidate, reviewers=(candidate != name))
                           for candidate in PRODUCTION_ENVS]
                with self.assertRaises(Exception):
                    self.check(list_payload(*entries))

    def test_reviewer_rule_without_reviewers_refuses(self):
        payload = list_payload(env_entry("release-tag"),
                               env_entry("crates-io", empty_reviewers=True),
                               env_entry("release"))
        with self.assertRaises(Exception):
            self.check(payload)

    def test_missing_environment_refuses(self):
        payload = list_payload(env_entry("release-tag"),
                               env_entry("crates-io"))
        with self.assertRaises(Exception):
            self.check(payload)

    def test_permissive_null_policy_refuses(self):
        # The captured `release` environment has no deployment
        # restriction at all; that must refuse, not pass silently.
        payload = list_payload(env_entry("release-tag"),
                               env_entry("crates-io"),
                               env_entry("release", policy="null"))
        with self.assertRaises(Exception):
            self.check(payload)

    def test_permissive_unrestricted_policy_refuses(self):
        payload = list_payload(env_entry("release-tag", policy="none"),
                               env_entry("crates-io"),
                               env_entry("release"))
        with self.assertRaises(Exception):
            self.check(payload)

    def test_mismatched_ref_pattern_refuses(self):
        policies = intended_policies()
        policies["crates-io"] = policies_payload(("branch", "main"))
        with self.assertRaises(Exception):
            self.check(protected_list(), policies)

    def test_extra_wildcard_policy_refuses(self):
        policies = intended_policies()
        policies["release"] = policies_payload(("tag", "v*"), ("tag", "*"))
        with self.assertRaises(Exception):
            self.check(protected_list(), policies)

    def test_empty_policy_list_refuses(self):
        policies = intended_policies()
        policies["release-tag"] = policies_payload()
        with self.assertRaises(Exception):
            self.check(protected_list(), policies)

    def test_missing_policy_readback_refuses(self):
        policies = intended_policies()
        del policies["crates-io"]
        with self.assertRaises(Exception):
            self.check(protected_list(), policies)

    def test_malformed_policy_entry_refuses(self):
        policies = intended_policies()
        policies["release"] = {"total_count": 1,
                               "branch_policies": [{"id": 1}]}
        with self.assertRaises(Exception):
            self.check(protected_list(), policies)

    def test_protected_branches_only_refuses(self):
        # Protected-branches-only is a restriction, but it is not the
        # documented selected-ref policy, so it must still refuse.
        payload = list_payload(env_entry("release-tag"),
                               env_entry("crates-io", policy="protected"),
                               env_entry("release"))
        with self.assertRaises(Exception):
            self.check(payload)

    def test_malformed_list_payload_refuses(self):
        for payload in ({}, {"total_count": 0}, {"environments": {}},
                        {"environments": "x"}, [], "[]", None, 42):
            with self.subTest(payload=payload):
                with self.assertRaises(Exception):
                    self.check(payload)

    def test_unknown_environment_has_no_contract(self):
        payload = list_payload(env_entry("staging"))
        with self.assertRaises(Exception):
            self.check(payload, {}, ("staging",))


class EnvironmentsPreflightCommandTests(unittest.TestCase):
    def write(self, directory, name, content):
        path = Path(directory) / name
        path.write_text(content, encoding="utf-8")
        return str(path)

    def check(self, *args):
        return release_checks.main(["environments-preflight", *args])

    def test_cli_passes_with_fixture_files(self):
        with tempfile.TemporaryDirectory() as temp:
            api = self.write(temp, "env.json", json.dumps(protected_list()))
            args = ["--api-json", api]
            for name, payload in intended_policies().items():
                policy_file = self.write(temp, name + ".json",
                                         json.dumps(payload))
                args += ["--policies-json", f"{name}={policy_file}"]
            self.assertEqual(self.check(*args), 0)

    def test_cli_checks_single_environment(self):
        with tempfile.TemporaryDirectory() as temp:
            payload = list_payload(env_entry("crates-io"))
            api = self.write(temp, "env.json", json.dumps(payload))
            policies = self.write(temp, "crates-io.json",
                                  json.dumps(policies_payload(("tag", "v*"))))
            self.assertEqual(self.check("--api-json", api,
                                        "--environment", "crates-io",
                                        "--policies-json",
                                        f"crates-io={policies}"), 0)

    def test_cli_refuses_absent_reviewers(self):
        with tempfile.TemporaryDirectory() as temp:
            payload = list_payload(env_entry("release", reviewers=False))
            api = self.write(temp, "env.json", json.dumps(payload))
            self.assertNotEqual(self.check("--api-json", api,
                                           "--environment", "release"), 0)

    def test_cli_refuses_missing_api_json(self):
        with tempfile.TemporaryDirectory() as temp:
            missing = str(Path(temp) / "no-such.json")
            self.assertNotEqual(self.check("--api-json", missing), 0)

    def test_cli_refuses_malformed_api_json(self):
        with tempfile.TemporaryDirectory() as temp:
            api = self.write(temp, "env.json", "{not json")
            self.assertNotEqual(self.check("--api-json", api), 0)

    def test_cli_refuses_malformed_policies_option(self):
        with tempfile.TemporaryDirectory() as temp:
            api = self.write(temp, "env.json", json.dumps(protected_list()))
            self.assertNotEqual(self.check("--api-json", api,
                                           "--policies-json",
                                           "missing-equals-sign"), 0)


class EnvironmentGateWorkflowTests(unittest.TestCase):
    GATES = ((CUT_YML, "verify", "release-tag"),
             (PUBLISH_YML, "preflight", "crates-io"),
             (RELEASE_YML, "recover", "release"))

    def gate_run(self, path, job_id, environment):
        workflow = load_workflow(path)
        job = workflow["jobs"][job_id]
        runs = [str(step.get("run", "")) for step in job.get("steps", [])
                if isinstance(step, dict)]
        gates = [run for run in runs if "environments-preflight" in run]
        self.assertEqual(len(gates), 1,
                         f"{path.name} {job_id} must run exactly one "
                         "environments-preflight gate")
        self.assertIn(f"--environment {environment}", gates[0])
        return gates[0]

    def test_each_pre_mutation_job_gates_its_environment(self):
        for path, job_id, environment in self.GATES:
            with self.subTest(job=job_id):
                self.gate_run(path, job_id, environment)

    def test_gate_reads_back_live_api_with_read_only_calls(self):
        for path, job_id, environment in self.GATES:
            with self.subTest(job=job_id):
                run = self.gate_run(path, job_id, environment)
                self.assertIn("gh api", run)
                self.assertIn("/environments", run)
                self.assertIn("--api-json", run)
                self.assertIn("--policies-json", run)
                self.assertNotIn("--method", run)
                self.assertNotIn("PUT", run)
                self.assertNotIn("POST", run)
                self.assertNotIn("DELETE", run)

    def test_publish_upload_stays_behind_preflight_and_env(self):
        workflow = load_workflow(PUBLISH_YML)
        upload = workflow["jobs"]["upload"]
        self.assertIn("preflight", upload.get("needs", []))
        self.assertEqual(upload.get("environment"), "crates-io")

    def test_release_publish_stays_behind_recover_and_env(self):
        workflow = load_workflow(RELEASE_YML)
        publish = workflow["jobs"]["publish"]
        self.assertIn("recover", publish.get("needs", []))
        self.assertEqual(publish.get("environment"), "release")

    def test_cut_stays_behind_verify_and_env(self):
        workflow = load_workflow(CUT_YML)
        cut = workflow["jobs"]["cut"]
        self.assertIn("verify", cut.get("needs", []))
        self.assertEqual(cut.get("environment"), "release-tag")


class ProtectionContractDocTests(unittest.TestCase):
    def test_contract_doc_specifies_gate_and_proposed_settings(self):
        self.assertTrue(CONTRACT.is_file(),
                        "doc/release/environment-protection-contract.md "
                        "must specify the protection contract")
        text = CONTRACT.read_text(encoding="utf-8")
        for name in PRODUCTION_ENVS:
            with self.subTest(environment=name):
                self.assertIn(name, text)
        for marker in ("environments-preflight", "required reviewers",
                       "deployment-branch-policies", "proposed settings",
                       "fail-closed", "gh api", "/environments"):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_contract_doc_states_plan_limits(self):
        text = CONTRACT.read_text(encoding="utf-8")
        self.assertIn("public repository", text)
        self.assertIn("private", text)


if __name__ == "__main__":
    unittest.main()

"""Q12 (RO-02) publication/qualification-evidence binding tests.

RED-FIRST: these tests describe the pre-publication qualification
gate: a helper (``scripts/release/package_qualification.py``) that
validates a portable candidate-bound comparison receipt plus its
provider-selection record against independently supplied source and
selection expectations, a ``release_checks.py qualification-preflight``
subcommand, an augmented version-2 evidence binding carrying the
immutable qualification artifact identity/digest, one gate step in
each pre-mutation release job (``cut-release.yml`` verify,
``publish.yml`` preflight, ``release.yml`` recover), durable
retention of the validated record as release assets, and the
qualification-binding contract doc. They fail until those exist.

Conventions follow ``test_release_environments.py``: YAML structure
assertions plus behavior tests of the shared CLI with controlled
fixtures. No live GitHub calls, uploads, tags, credentials, or
network. A quality-only URL, a mutable or unbound provider record, a
missing provider row, an incomplete or failed comparison, a wrong
source/tree/lock, a changed referenced artifact, or a mismatched
framework/provider/config/test selection must all refuse before any
credential use or external mutation.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
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
CUT_YML = ROOT / ".github" / "workflows" / "cut-release.yml"
PUBLISH_YML = ROOT / ".github" / "workflows" / "publish.yml"
RELEASE_YML = ROOT / ".github" / "workflows" / "release.yml"
CONTRACT = ROOT / "doc" / "release" / "qualification-binding-contract.md"
CHECKLIST = ROOT / "doc" / "release" / "0.x-beta-release-checklist.md"
GUIDE = ROOT / "doc" / "release" / "crates-io-publishing.md"
SCRIPTS_README = ROOT / "scripts" / "README.md"

# Current release policy: the explicit 30-provider non-mock matrix.
# Mirrors the pooled-runner matrix minus pkcs11-mock and minus the
# heavy/manual OP-TEE targets. Pinned here; the implementation must
# match exactly and must never relabel omitted rows as success.
EXPECTED_PROVIDERS = frozenset({
    "softhsm2", "softhsm2-main", "softhsm2-generated-iv",
    "kryoptic", "kryoptic-main", "kryoptic-fips",
    "nss", "nss-slot0", "nss-main", "nss-main-slot0",
    "nss-pqc", "nss-pqc-slot0",
    "opencryptoki", "opencryptoki-master",
    "bouncyhsm", "tpm2",
    "wolfpkcs11", "wolfpkcs11-master",
    "corepkcs11", "corepkcs11-main",
    "craton-hsm", "freehsm-c", "nethsm", "jcardsim", "cryptech",
    "kmsp11", "cosmian",
    "wolfpkcs11-tpm", "wolfpkcs11-tpm-release",
    "pico-hsm",
})

SUBJECT = "a" * 40
TREE = "b" * 40
FRAMEWORK = "c" * 40
RUN_ID = "37423315928"
COMPARISON_FORMAT = "pool-comparison/v1"
CONFIG_NAME = "pooled-release-default"
SELECTION_NAME = "full-matrix"
IMMUTABLE_URL = ("https://github.com/example/pkcs11-proxy-ng/blob/"
                 + "d" * 40 + "/qualification/evidence")
MUTABLE_URL = ("https://github.com/example/pkcs11-proxy-ng/blob/main/"
               "doc/release/v0.2.2-quality-receipt.md")

sys.path.insert(0, str(ROOT / "scripts"))
import release_checks  # noqa: E402


def load_qualification():
    package_dir = str(ROOT / "scripts")
    if package_dir not in sys.path:
        sys.path.insert(0, package_dir)
    import release.package_qualification as qual

    return qual


def load_workflow(path):
    if yaml is None:
        raise unittest.SkipTest("PyYAML is required to parse workflows")
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pass_row(run_id=RUN_ID):
    return {"run_id": run_id, "gate": "PASS", "complete": True,
            "regressions": 0, "known": 0, "improvements": 0,
            "both_nonpass": 0, "direct_only": 0, "proxy_only": 0,
            "incomplete": 0, "incomplete_reasons": [], "disposition": "",
            "evidence": ""}


def make_record(*, subject=SUBJECT, framework=FRAMEWORK, run_id=RUN_ID,
                providers=None):
    names = sorted(EXPECTED_PROVIDERS) if providers is None else providers
    return {"format": "pool-evidence/v1", "run_id": run_id,
            "candidate": {"commit": subject,
                          "describe": "v9.9.9-1-g" + subject[:8]},
            "framework": {"commit": framework},
            "generated_at": "2026-10-06T03:14:00Z",
            "evidence_root": "",
            "providers": {name: pass_row(run_id) for name in names}}


def comparison_row():
    return {"gate": "PASS", "complete": True}


def make_comparison(*, run_id=RUN_ID, config=CONFIG_NAME,
                    test_selection=SELECTION_NAME, providers=None,
                    fmt=COMPARISON_FORMAT):
    names = sorted(EXPECTED_PROVIDERS) if providers is None else providers
    return {"format": fmt, "run_id": run_id,
            "config": config, "test_selection": test_selection,
            "providers": {name: comparison_row() for name in names}}


def write_evidence(root, *, subject=SUBJECT, tree=TREE,
                   lock_contents=b"frozen Cargo.lock\n",
                   framework=FRAMEWORK, run_id=RUN_ID, record=None,
                   receipt_kind="comparison", manifests=None,
                   comparison=None, comparison_bytes=None):
    """Build a complete evidence dir; return pinned digests + receipt."""
    bundle = Path(root) / "bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "Cargo.lock").write_bytes(lock_contents)
    lock_sha = sha256_bytes(lock_contents)
    payloads = {"framework": {"commit": framework},
                "corpora": {"corpora": ["pkcs11-check-corpus-1"]},
                "provider": {"providers": sorted(EXPECTED_PROVIDERS)},
                "config": {"config": CONFIG_NAME},
                "selection": {"run_id": run_id,
                              "test_selection": SELECTION_NAME}}
    payloads.update(manifests or {})
    refs = {}
    for role, payload in payloads.items():
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        (bundle / f"{role}.json").write_bytes(data)
        refs[role] = {"path": f"{role}.json",
                      "sha256": sha256_bytes(data)}
    if comparison_bytes is not None:
        comparison_raw = comparison_bytes
    else:
        payload = (make_comparison(run_id=run_id)
                   if comparison is None else comparison)
        comparison_raw = (json.dumps(payload, sort_keys=True) + "\n").encode(
            "utf-8")
    (bundle / "comparison.json").write_bytes(comparison_raw)
    record = make_record() if record is None else record
    record_data = json.dumps(record, sort_keys=True).encode("utf-8")
    (bundle / "pool-evidence.json").write_bytes(record_data)
    receipt = {"schema_version": 1, "kind": receipt_kind,
               "classification": "candidate-bound",
               "source": {"commit": subject, "tree": tree,
                          "lock": {"path": "Cargo.lock",
                                   "sha256": lock_sha}},
               "toolchain": {"rustc": "rustc 1.98.1",
                             "cargo": "cargo 1.98.1",
                             "target": "x86_64-unknown-linux-gnu"},
               "binaries": {},
               "identities": refs,
               "completion": {"complete": True, "outcome": "passed"},
               "artifacts": {
                   "comparison": {
                       "path": "comparison.json",
                       "sha256": sha256_bytes(comparison_raw)},
                   "pool_evidence": {
                       "path": "pool-evidence.json",
                       "sha256": sha256_bytes(record_data)}}}
    receipt_data = json.dumps(receipt, sort_keys=True).encode("utf-8")
    (Path(root) / "receipt.json").write_bytes(receipt_data)
    return {"lock_sha256": lock_sha,
            "record_sha256": sha256_bytes(record_data),
            "receipt_sha256": sha256_bytes(receipt_data),
            "receipt": receipt, "record": record}


class QualificationPolicyTests(unittest.TestCase):
    def test_required_provider_set_is_exact_thirty(self):
        qual = load_qualification()
        self.assertEqual(len(EXPECTED_PROVIDERS), 30)
        self.assertNotIn("pkcs11-mock", EXPECTED_PROVIDERS)
        self.assertEqual(set(qual.REQUIRED_PROVIDERS), EXPECTED_PROVIDERS)
        self.assertEqual(list(qual.REQUIRED_PROVIDERS),
                         sorted(EXPECTED_PROVIDERS))

    def test_evidence_layout_constants(self):
        qual = load_qualification()
        self.assertEqual(qual.EVIDENCE_ARTIFACT_NAME,
                         "provider-qualification")
        self.assertEqual(qual.RECEIPT_FILENAME, "receipt.json")
        self.assertEqual(qual.RECORD_FILENAME, "pool-evidence.json")
        self.assertEqual(qual.RECORD_ROLE, "pool_evidence")


class QualificationUrlTests(unittest.TestCase):
    def test_accepts_immutable_subject_and_version_urls(self):
        qual = load_qualification()
        frozen = "e" * 40
        for url in (
                IMMUTABLE_URL,
                f"https://github.com/o/r/blob/{frozen}/q/evidence",
                f"https://github.com/o/r/releases/download/v0.2.3/"
                "qualification-record.json",
                "https://github.com/o/r/releases/tag/v0.2.3",
                "https://github.com/o/r/actions/runs/37423315928",
        ):
            with self.subTest(url=url):
                self.assertTrue(qual.immutable_qualification_url(url))

    def test_refuses_mutable_or_malformed_urls(self):
        qual = load_qualification()
        for url in (
                MUTABLE_URL,  # the v0.2.2 failure mode: /blob/main/
                "https://example.invalid/blob/master/evidence",
                "https://example.invalid/evidence/latest/record.json",
                "https://example.invalid/HEAD/record.json",
                "https://example.invalid/qualification",  # no marker
                "http://example.invalid/blob/" + "f" * 40 + "/q",
                "https://user:secret@example.invalid/" + "f" * 40,
                "https:///missing-host/" + "f" * 40,
                "",
        ):
            with self.subTest(url=url):
                self.assertFalse(qual.immutable_qualification_url(url))


class QualificationGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workdir = Path(self.temp.name)

    def gate(self, evidence_dir, *, url=IMMUTABLE_URL, subject=SUBJECT,
             tree=TREE, framework=FRAMEWORK, run_id=RUN_ID,
             record_sha256=None, receipt_sha256=None, lock_sha256=None):
        args = ["qualification-preflight",
                "--evidence-dir", str(evidence_dir),
                "--expect-commit", subject,
                "--expect-tree", tree,
                "--expect-lock-sha256",
                lock_sha256 if lock_sha256 is not None else "0" * 64,
                "--expect-framework", framework,
                "--expect-run-id", run_id,
                "--expect-url", url,
                "--expect-record-sha256",
                record_sha256 if record_sha256 is not None else "0" * 64,
                "--expect-receipt-sha256",
                receipt_sha256 if receipt_sha256 is not None else "0" * 64]
        return release_checks.main(args, repo=ROOT)

    def valid(self, **overrides):
        target = self.workdir / "evidence"
        if target.exists():
            raise AssertionError("write_evidence target already exists")
        built = write_evidence(target, **overrides)
        params = {"lock_sha256": built["lock_sha256"],
                  "record_sha256": built["record_sha256"],
                  "receipt_sha256": built["receipt_sha256"]}
        return target, built, params

    def test_accepts_complete_bound_qualification(self):
        import io
        from contextlib import redirect_stdout
        target, _built, params = self.valid()
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = self.gate(target, **params)
        self.assertEqual(code, 0)
        summary = buffer.getvalue()
        self.assertIn(SUBJECT, summary)
        self.assertIn(FRAMEWORK, summary)
        self.assertIn(RUN_ID, summary)
        self.assertIn("30", summary)

    def test_refuses_quality_only_or_missing_evidence(self):
        # A quality-only URL carries no provider record at all: the
        # syntax-valid URL alone cannot satisfy qualification.
        target, _built, params = self.valid()
        missing = self.workdir / "absent"
        self.assertEqual(self.gate(missing, **params), 1)
        empty = self.workdir / "empty"
        empty.mkdir()
        self.assertEqual(self.gate(empty, **params), 1)
        (target / "bundle" / "pool-evidence.json").unlink()
        self.assertEqual(self.gate(target, **params), 1)

    def test_refuses_non_comparison_receipt(self):
        target, _built, params = self.valid(receipt_kind="build")
        self.assertEqual(self.gate(target, **params), 1)

    def test_refuses_mutable_qualification_url(self):
        target, _built, params = self.valid()
        self.assertEqual(self.gate(target, url=MUTABLE_URL, **params), 1)

    def test_refuses_unbound_provider_record(self):
        # not_applicable identities are unbound: qualification must
        # pin framework, corpora, provider, config, and selection.
        target, _built, params = self.valid()
        receipt_path = target / "receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["identities"]["provider"] = {"not_applicable": "tbd"}
        receipt_data = json.dumps(receipt, sort_keys=True).encode("utf-8")
        receipt_path.write_bytes(receipt_data)
        params = dict(params,
                      receipt_sha256=sha256_bytes(receipt_data))
        self.assertEqual(self.gate(target, **params), 1)

    def test_refuses_receipt_or_record_digest_mismatch(self):
        target, _built, params = self.valid()
        wrong = dict(params, record_sha256="0" * 64)
        self.assertEqual(self.gate(target, **wrong), 1)
        wrong = dict(params, receipt_sha256="0" * 64)
        self.assertEqual(self.gate(target, **wrong), 1)

    def test_refuses_receipt_missing_the_record_reference(self):
        target, built, params = self.valid()
        receipt = dict(built["receipt"])
        del receipt["artifacts"]["pool_evidence"]
        receipt_data = json.dumps(receipt, sort_keys=True).encode("utf-8")
        (target / "receipt.json").write_bytes(receipt_data)
        params = dict(params, receipt_sha256=sha256_bytes(receipt_data))
        self.assertEqual(self.gate(target, **params), 1)

    def test_refuses_missing_comparison_reference(self):
        # C1: the receipt must digest-bind comparison evidence. A
        # receipt carrying only the pool record — with the receipt
        # digest re-pinned so the envelope is otherwise valid —
        # cannot qualify publication.
        target, built, params = self.valid()
        receipt = dict(built["receipt"])
        del receipt["artifacts"]["comparison"]
        receipt_data = json.dumps(receipt, sort_keys=True).encode("utf-8")
        (target / "receipt.json").write_bytes(receipt_data)
        params = dict(params, receipt_sha256=sha256_bytes(receipt_data))
        self.assertEqual(self.gate(target, **params), 1)

    def test_refuses_non_json_comparison(self):
        # C1: comparison bytes are parsed, not just hash-checked.
        # The artifact and receipt digests stay valid; only the
        # comparison semantics change.
        target = self.workdir / "evidence-nonjson-comparison"
        built = write_evidence(target, comparison_bytes=b"not json{{{")
        params = {"lock_sha256": built["lock_sha256"],
                  "record_sha256": built["record_sha256"],
                  "receipt_sha256": built["receipt_sha256"]}
        self.assertEqual(self.gate(target, **params), 1)

    def test_refuses_failed_or_incomplete_comparison_payload(self):
        # C1: every negative below keeps valid hashes (write_evidence
        # re-pins the artifact and receipt digests) and changes only
        # comparison semantics: each must refuse.
        names = sorted(EXPECTED_PROVIDERS)
        failed = make_comparison()
        failed["providers"][names[0]] = {"gate": "FAIL", "complete": True}
        incomplete = make_comparison()
        incomplete["providers"][names[0]] = {"gate": "INCOMPLETE",
                                             "complete": False}
        cases = {
            "failed-row": failed,
            "incomplete-row": incomplete,
            "missing-row": make_comparison(providers=names[:-1]),
            "extra-row": make_comparison(
                providers=names + ["stray-provider"]),
            "wrong-run": make_comparison(run_id="1"),
            "wrong-format": make_comparison(fmt="comparison/v9"),
        }
        for label, comparison in cases.items():
            with self.subTest(case=label):
                target = self.workdir / f"evidence-comparison-{label}"
                built = write_evidence(target, comparison=comparison)
                params = {"lock_sha256": built["lock_sha256"],
                          "record_sha256": built["record_sha256"],
                          "receipt_sha256": built["receipt_sha256"]}
                self.assertEqual(self.gate(target, **params), 1)

    def test_refuses_missing_extra_or_mock_provider_rows(self):
        names = sorted(EXPECTED_PROVIDERS)
        cases = {
            "missing-row": names[:-1],
            "extra-row": names + ["stray-provider"],
            "mock-row": names[:-1] + ["pkcs11-mock"],
            "swapped-row": names[:-1] + ["other-provider"],
        }
        for label, providers in cases.items():
            with self.subTest(case=label):
                target = self.workdir / f"evidence-{label}"
                record = make_record(providers=providers)
                built = write_evidence(target, record=record)
                params = {"lock_sha256": built["lock_sha256"],
                          "record_sha256": built["record_sha256"],
                          "receipt_sha256": built["receipt_sha256"]}
                self.assertEqual(self.gate(target, **params), 1)

    def test_refuses_incomplete_or_failed_comparison(self):
        # I3: both fixtures are otherwise-valid completed rows, so
        # refusal must come from the qualification gate (no passing
        # comparison) — not from support-matrix shape validation. The
        # FAIL row carries gate="FAIL" with a recorded disposition.
        import io
        from contextlib import redirect_stderr
        for gate, mutate in (
                ("INCOMPLETE",
                 lambda row: row.update(complete=False, gate="INCOMPLETE",
                                        incomplete_reasons=["stalled"])),
                ("FAIL",
                 lambda row: row.update(gate="FAIL",
                                        disposition="regression triaged"))):
            with self.subTest(gate=gate):
                target = self.workdir / f"evidence-{gate.lower()}"
                record = make_record()
                first = sorted(record["providers"])[0]
                mutate(record["providers"][first])
                built = write_evidence(target, record=record)
                params = {"lock_sha256": built["lock_sha256"],
                          "record_sha256": built["record_sha256"],
                          "receipt_sha256": built["receipt_sha256"]}
                buffer = io.StringIO()
                with redirect_stderr(buffer):
                    code = self.gate(target, **params)
                self.assertEqual(code, 1)
                self.assertIn("has no passing comparison",
                              buffer.getvalue())

    def test_refuses_mixed_run_merge(self):
        target = self.workdir / "evidence-mixed"
        record = make_record()
        first = sorted(record["providers"])[0]
        record["providers"][first]["run_id"] = "999"
        built = write_evidence(target, record=record)
        params = {"lock_sha256": built["lock_sha256"],
                  "record_sha256": built["record_sha256"],
                  "receipt_sha256": built["receipt_sha256"]}
        self.assertEqual(self.gate(target, **params), 1)

    def test_refuses_wrong_source_tree_or_lock(self):
        target, _built, params = self.valid()
        for label, override in (
                ("commit", {"subject": "0" * 40}),
                ("tree", {"tree": "0" * 40}),
                ("lock", {"lock_sha256": "0" * 64})):
            with self.subTest(field=label):
                args = dict(params)
                args.update(override)
                self.assertEqual(self.gate(target, **args), 1)

    def test_refuses_changed_referenced_artifact(self):
        target, _built, params = self.valid()
        (target / "bundle" / "comparison.json").write_bytes(b"tampered")
        self.assertEqual(self.gate(target, **params), 1)

    def test_refuses_mismatched_framework_provider_or_selection(self):
        target, _built, params = self.valid()
        cases = {
            # expectation disagrees with the validated record
            "framework-expectation": {"framework": "0" * 40},
            "run-expectation": {"run_id": "1"},
            "subject-expectation": {"subject": "0" * 40},
        }
        for label, override in cases.items():
            with self.subTest(case=label):
                args = dict(params)
                args.update(override)
                self.assertEqual(self.gate(target, **args), 1)
        # manifest disagrees with the expected selection
        bad_manifests = {
            "framework-manifest":
                {"framework": {"commit": "0" * 40}},
            "provider-manifest":
                {"provider": {"providers": ["only-one"]}},
            "selection-manifest":
                {"selection": {"run_id": "1",
                               "test_selection": "full-matrix"}},
            "empty-test-selection":
                {"selection": {"run_id": RUN_ID, "test_selection": ""}},
            "empty-config":
                {"config": {"config": ""}},
        }
        for label, manifests in bad_manifests.items():
            with self.subTest(case=label):
                target = self.workdir / f"evidence-{label}"
                built = write_evidence(target, manifests=manifests)
                args = {"lock_sha256": built["lock_sha256"],
                        "record_sha256": built["record_sha256"],
                        "receipt_sha256": built["receipt_sha256"]}
                self.assertEqual(self.gate(target, **args), 1)

    def test_refuses_config_or_selection_disagreement(self):
        # I1: nonempty config/test-selection values must agree
        # across the config manifest, the selection manifest, and
        # the comparison payload. Every case below keeps valid
        # hashes; only the identity relationship breaks.
        disagreements = {
            "config-manifest-differs":
                ({"config": {"config": "other-config"}}, None),
            "selection-manifest-differs":
                ({"selection": {"run_id": RUN_ID,
                                "test_selection": "one-test-only"}},
                 None),
            "comparison-config-differs":
                (None, make_comparison(config="other-config")),
            "comparison-selection-differs":
                (None, make_comparison(test_selection="one-test-only")),
            "comparison-config-empty":
                (None, make_comparison(config="")),
            "comparison-selection-empty":
                (None, make_comparison(test_selection="")),
        }
        for label, (manifests, comparison) in disagreements.items():
            with self.subTest(case=label):
                target = self.workdir / f"evidence-{label}"
                built = write_evidence(target, manifests=manifests,
                                       comparison=comparison)
                args = {"lock_sha256": built["lock_sha256"],
                        "record_sha256": built["record_sha256"],
                        "receipt_sha256": built["receipt_sha256"]}
                self.assertEqual(self.gate(target, **args), 1)


TAG_COMMIT = "6b151b799b59bce4a06f6cb993f8a74a84ae0481"
CANDIDATE_RUN_ID = "12345678"
QUAL_SUBJECT = "abc123def456abc123def456abc123def456abcd"
RECEIPT_SHA = "1" * 64
RECORD_SHA = "2" * 64


class BindingVersionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workdir = Path(self.temp.name)

    def bind_args(self, output, **overrides):
        args = ["evidence-bind", "--output", str(output),
                "--tag-commit", TAG_COMMIT, "--run-id", CANDIDATE_RUN_ID,
                "--qualification-url", IMMUTABLE_URL,
                "--qualification-subject", QUAL_SUBJECT,
                "--qualification-receipt-sha256", RECEIPT_SHA,
                "--qualification-record-sha256", RECORD_SHA,
                "--qualification-run-id", RUN_ID,
                "--qualification-framework", FRAMEWORK]
        for key, value in overrides.items():
            flag = "--" + key.replace("_", "-")
            args[args.index(flag) + 1] = value
        return args

    def verify_args(self, binding, **overrides):
        args = ["evidence-verify", "--binding", str(binding),
                "--expect-url", IMMUTABLE_URL,
                "--expect-subject", QUAL_SUBJECT,
                "--expect-tag-commit", TAG_COMMIT,
                "--expect-run-id", CANDIDATE_RUN_ID,
                "--expect-receipt-sha256", RECEIPT_SHA,
                "--expect-record-sha256", RECORD_SHA,
                "--expect-qual-run-id", RUN_ID,
                "--expect-framework", FRAMEWORK]
        for key, value in overrides.items():
            flag = "--" + key.replace("_", "-")
            args[args.index(flag) + 1] = value
        return args

    def test_bind_writes_version_two_with_qualification_identity(self):
        binding = self.workdir / "binding.json"
        self.assertEqual(
            release_checks.main(self.bind_args(binding), repo=ROOT), 0)
        payload = json.loads(binding.read_text(encoding="utf-8"))
        self.assertEqual(payload["format_version"], 2)
        self.assertEqual(payload["qualification_receipt_sha256"],
                         RECEIPT_SHA)
        self.assertEqual(payload["qualification_record_sha256"], RECORD_SHA)
        self.assertEqual(payload["qualification_run_id"], RUN_ID)
        self.assertEqual(payload["qualification_framework"], FRAMEWORK)
        # Frozen source/candidate identities are preserved.
        self.assertEqual(payload["tag_commit"], TAG_COMMIT)
        self.assertEqual(payload["run_id"], CANDIDATE_RUN_ID)
        self.assertEqual(payload["qualification_subject"], QUAL_SUBJECT)

    def test_bind_requires_qualification_identity(self):
        # URL-only bindings can no longer be written: the writer
        # refuses without the immutable qualification identity.
        binding = self.workdir / "binding.json"
        args = self.bind_args(binding)
        args.remove("--qualification-record-sha256")
        args.remove(RECORD_SHA)
        with self.assertRaises(SystemExit) as refused:
            release_checks.main(args, repo=ROOT)
        self.assertNotEqual(refused.exception.code, 0)
        self.assertFalse(binding.exists())

    def test_verify_accepts_exact_version_two_binding(self):
        binding = self.workdir / "binding.json"
        self.assertEqual(
            release_checks.main(self.bind_args(binding), repo=ROOT), 0)
        self.assertEqual(
            release_checks.main(self.verify_args(binding), repo=ROOT), 0)

    def test_verify_refuses_drifted_qualification_identity(self):
        binding = self.workdir / "binding.json"
        self.assertEqual(
            release_checks.main(self.bind_args(binding), repo=ROOT), 0)
        for overrides in ({"expect_receipt_sha256": "0" * 64},
                          {"expect_record_sha256": "0" * 64},
                          {"expect_qual_run_id": "1"},
                          {"expect_framework": "0" * 40}):
            with self.subTest(overrides=overrides):
                self.assertEqual(
                    release_checks.main(
                        self.verify_args(binding, **overrides),
                        repo=ROOT), 1)

    def write_v1(self):
        # A pre-Q12 URL-only binding, byte-shaped like v0.2.2's.
        binding = self.workdir / "v1.json"
        binding.write_text(json.dumps(
            {"format_version": 1,
             "artifact": f"crates-candidate-{TAG_COMMIT}-{CANDIDATE_RUN_ID}",
             "qualification_subject": QUAL_SUBJECT,
             "qualification_url": IMMUTABLE_URL,
             "run_id": CANDIDATE_RUN_ID,
             "tag_commit": TAG_COMMIT}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        return binding

    def test_version_one_binding_stays_readable_but_unpublishable(self):
        # Reader compatibility: v1 bindings still read and verify
        # their legacy fields, but any v2 qualification expectation
        # refuses them instead of silently misreading them.
        binding = self.write_v1()
        legacy = ["evidence-verify", "--binding", str(binding),
                  "--expect-url", IMMUTABLE_URL,
                  "--expect-subject", QUAL_SUBJECT,
                  "--expect-tag-commit", TAG_COMMIT,
                  "--expect-run-id", CANDIDATE_RUN_ID]
        self.assertEqual(release_checks.main(legacy, repo=ROOT), 0)
        self.assertEqual(
            release_checks.main(self.verify_args(binding), repo=ROOT), 1)

    def test_unknown_binding_version_refuses(self):
        binding = self.workdir / "future.json"
        binding.write_text(json.dumps(
            {"format_version": 99, "tag_commit": TAG_COMMIT}),
            encoding="utf-8")
        self.assertEqual(
            release_checks.main(self.verify_args(binding), repo=ROOT), 1)


NEW_QUAL_INPUTS = ("qualification-run-id", "qualification-framework",
                   "qualification-record-sha256",
                   "qualification-receipt-sha256")


def run_text(job):
    return "\n".join(step.get("run", "") for step in job.get("steps", [])
                     if isinstance(step, dict))


class QualificationWorkflowTests(unittest.TestCase):
    def test_new_qualification_inputs_on_all_release_workflows(self):
        for path in (CUT_YML, PUBLISH_YML, RELEASE_YML):
            with self.subTest(workflow=path.name):
                workflow = load_workflow(path)
                triggers = workflow.get("on", workflow.get(True, {}))
                if path == RELEASE_YML:
                    for trigger in ("workflow_call", "workflow_dispatch"):
                        inputs = triggers[trigger]["inputs"]
                        for name in NEW_QUAL_INPUTS:
                            self.assertIn(name, inputs)
                else:
                    inputs = triggers["workflow_dispatch"]["inputs"]
                    for name in NEW_QUAL_INPUTS:
                        self.assertIn(name, inputs)

    def test_release_qualification_inputs_are_required(self):
        workflow = load_workflow(RELEASE_YML)
        triggers = workflow.get("on", workflow.get(True, {}))
        for trigger in ("workflow_call", "workflow_dispatch"):
            inputs = triggers[trigger]["inputs"]
            for name in ("qualification-url", "qualification-subject",
                         *NEW_QUAL_INPUTS):
                with self.subTest(trigger=trigger, input=name):
                    self.assertTrue(inputs[name].get("required"))

    def test_gate_step_in_each_pre_mutation_job(self):
        # The gate composes with Q11's environments-preflight step:
        # both run before any credential use or mutation, in the
        # same jobs, without duplicating or bypassing each other.
        jobs = {"cut-release.yml": ("verify",),
                "publish.yml": ("preflight",),
                "release.yml": ("recover",)}
        for name, job_ids in jobs.items():
            workflow = load_workflow(ROOT / ".github" / "workflows" / name)
            for job_id in job_ids:
                with self.subTest(workflow=name, job=job_id):
                    job = workflow["jobs"][job_id]
                    text = run_text(job)
                    self.assertIn("environments-preflight", text)
                    self.assertIn("qualification-preflight", text)
                    self.assertIn("provider-qualification", text)
                    self.assertIn("--expect-record-sha256", text)
                    self.assertIn("--expect-receipt-sha256", text)

    def test_gate_steps_use_read_only_evidence_download(self):
        for path, job_id in ((CUT_YML, "verify"),
                             (PUBLISH_YML, "preflight"),
                             (RELEASE_YML, "recover")):
            with self.subTest(workflow=path.name):
                job = load_workflow(path)["jobs"][job_id]
                text = run_text(job)
                self.assertIn("gh run download", text)
                self.assertIn("QUALIFICATION_RUN_ID", text)

    def test_publish_upload_recheck_covers_qualification_identity(self):
        job = load_workflow(PUBLISH_YML)["jobs"]["upload"]
        text = run_text(job)
        for flag in ("--qualification-url", "--qualification-subject",
                     "--qualification-run-id", "--qualification-framework",
                     "--qualification-record-sha256",
                     "--qualification-receipt-sha256"):
            with self.subTest(flag=flag):
                self.assertIn(flag, text)

    def test_candidate_binds_qualification_identity(self):
        job = load_workflow(PUBLISH_YML)["jobs"]["candidate"]
        text = run_text(job)
        self.assertIn("evidence-bind", text)
        for flag in ("--qualification-receipt-sha256",
                     "--qualification-record-sha256",
                     "--qualification-run-id", "--qualification-framework"):
            with self.subTest(flag=flag):
                self.assertIn(flag, text)

    def test_recover_reverifies_qualification_identity(self):
        job = load_workflow(RELEASE_YML)["jobs"]["recover"]
        text = run_text(job)
        self.assertIn("evidence-verify", text)
        for flag in ("--expect-receipt-sha256", "--expect-record-sha256",
                     "--expect-qual-run-id", "--expect-framework"):
            with self.subTest(flag=flag):
                self.assertIn(flag, text)

    def test_validated_record_archived_as_release_asset(self):
        # Durable retention alongside provenance: the validated
        # record and receipt ship as release assets, not just
        # 90-day run artifacts — and the complete validated evidence
        # bundle ships as an archive preserving the relative layout,
        # so the portable validator can revalidate after run expiry.
        # (I2: receipt-only retention leaves no revalidatable bundle
        # once the qualification artifact expires.)
        job = load_workflow(RELEASE_YML)["jobs"]["publish"]
        text = run_text(job)
        self.assertIn("qualification-record.json", text)
        self.assertIn("qualification-receipt.json", text)
        self.assertIn("qualification-evidence.tar.gz", text)
        recover = run_text(load_workflow(RELEASE_YML)["jobs"]["recover"])
        self.assertIn("qualification-record.json", recover)
        self.assertIn("qualification-receipt.json", recover)
        self.assertIn("qualification-evidence.tar.gz", recover)
        self.assertIn("tar ", recover)

    def test_recovery_archive_deterministic_across_extraction_metadata(self):
        # N1: recovery regenerates qualification-evidence.tar.gz on
        # every retry, and the publish compare gate refuses divergent
        # bytes — so extraction metadata (timestamps, ownership,
        # traversal order) must not leak into the archive, or a retry
        # over identical validated evidence refuses as divergent.
        # Run the workflow's own archive command twice over
        # byte-identical evidence with differing mtimes; the digests
        # must match and pass the real assets-compare.
        if shutil.which("tar") is None or shutil.which("gzip") is None:
            raise unittest.SkipTest("tar and gzip are required")
        if shutil.which("bash") is None:
            raise unittest.SkipTest("bash is required")
        job = load_workflow(RELEASE_YML)["jobs"]["recover"]
        steps = [step for step in job.get("steps", [])
                 if isinstance(step, dict)
                 and "qualification-evidence.tar.gz" in step.get("run", "")
                 and "tar " in step.get("run", "")]
        self.assertEqual(len(steps), 1)
        joined, buf = [], ""
        for line in steps[0]["run"].splitlines():
            stripped = line.rstrip()
            if stripped.endswith("\\"):
                buf += stripped[:-1] + " "
            else:
                buf += stripped
                joined.append(buf)
                buf = ""
        if buf:
            joined.append(buf)
        commands = [line.strip() for line in joined
                    if "tar " in line
                    and "qualification-evidence.tar.gz" in line]
        self.assertEqual(len(commands), 1)
        command = commands[0]
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            first = work / "first-evidence"
            second = work / "second-evidence"
            first.mkdir()
            second.mkdir()
            write_evidence(first)
            write_evidence(second)
            # Same validated bytes, differing extraction metadata:
            # shift every mtime in the second tree (content untouched).
            shifted = 1_700_000_000
            for path in sorted(second.rglob("*")):
                os.utime(path, (shifted, shifted))
            os.utime(second, (shifted, shifted))
            digests = []
            for index, evidence in enumerate((first, second)):
                archive = work / f"attempt-{index}.tar.gz"
                adapted = command.replace("$RUNNER_TEMP/qual-evidence",
                                          str(evidence))
                adapted = adapted.replace(
                    "recovered/qualification-evidence.tar.gz",
                    str(archive))
                subprocess.run(["bash", "-c", adapted], check=True,
                               capture_output=True, text=True)
                digests.append(sha256_bytes(archive.read_bytes()))
            existing = [{"name": "qualification-evidence.tar.gz",
                         "sha256": digests[0]}]
            prepared = [{"name": "qualification-evidence.tar.gz",
                         "sha256": digests[1],
                         "path": "prepared/qualification-evidence.tar.gz"}]
            existing_path = work / "existing.json"
            prepared_path = work / "prepared.json"
            existing_path.write_text(json.dumps(existing), encoding="utf-8")
            prepared_path.write_text(json.dumps(prepared), encoding="utf-8")
            decision = release_checks.main(
                ["assets-compare", "--existing-json", str(existing_path),
                 "--prepared-json", str(prepared_path)], repo=ROOT)
            self.assertEqual(
                decision, 0,
                "retry over identical validated evidence refused: "
                f"{digests[0]} vs {digests[1]}")
            self.assertEqual(digests[0], digests[1])
        for flag in ("--sort=name", "--numeric-owner", "--mtime=",
                     "--owner=", "--group=", "gzip -n"):
            with self.subTest(flag=flag):
                self.assertIn(flag, command)

    def test_attestation_predicate_binds_qualification_identity(self):
        workflow = load_workflow(RELEASE_YML)
        job = workflow["jobs"]["publish"]
        predicates = [step for step in job.get("steps", [])
                      if isinstance(step, dict)
                      and step.get("id") == "predicate"]
        self.assertEqual(len(predicates), 1)
        block = predicates[0]["run"]
        for key in ("qualification_record_sha256",
                    "qualification_receipt_sha256",
                    "qualification_run_id", "qualification_framework"):
            with self.subTest(key=key):
                self.assertIn(key, block)

    def test_cut_dispatch_passes_qualification_identity_once(self):
        job = load_workflow(CUT_YML)["jobs"]["dispatch-publish"]
        text = run_text(job)
        for flag in ("qualification-run-id=", "qualification-framework=",
                     "qualification-record-sha256=",
                     "qualification-receipt-sha256="):
            with self.subTest(flag=flag):
                self.assertIn(flag, text)

    def test_publish_recovery_command_passes_qualification_identity(self):
        workflow = load_workflow(PUBLISH_YML)
        job = workflow["jobs"]["dispatch-release"]
        text = run_text(job)
        for flag in ("qualification-run-id=", "qualification-framework=",
                     "qualification-record-sha256=",
                     "qualification-receipt-sha256="):
            with self.subTest(flag=flag):
                self.assertIn(flag, text)


class QualificationDocsTests(unittest.TestCase):
    def test_contract_doc_exists_with_required_sections(self):
        text = CONTRACT.read_text(encoding="utf-8")
        for marker in ("format_version", "30-provider",
                       "provider-qualification",
                       "qualification-record.json",
                       "qualification-evidence.tar.gz",
                       "pool-comparison/v1",
                       "retention", "waiver",
                       "qualification-preflight",
                       "immutable"):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)
        for provider in ("softhsm2", "kryoptic", "nss", "pico-hsm",
                         "craton-hsm"):
            with self.subTest(provider=provider):
                self.assertIn(provider, text)

    def test_checklist_names_qualification_record_gate(self):
        text = CHECKLIST.read_text(encoding="utf-8")
        self.assertIn("qualification-record.json", text)
        self.assertIn("qualification-preflight", text)

    def test_guide_names_new_qualification_inputs(self):
        text = GUIDE.read_text(encoding="utf-8")
        for name in NEW_QUAL_INPUTS:
            with self.subTest(input=name):
                self.assertIn(name, text)

    def test_scripts_readme_names_qualification_gate(self):
        text = SCRIPTS_README.read_text(encoding="utf-8")
        self.assertIn("qualification-preflight", text)


if __name__ == "__main__":
    unittest.main()

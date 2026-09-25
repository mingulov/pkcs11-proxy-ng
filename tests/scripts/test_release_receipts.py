"""Portable receipt validation exercised through the standalone CLI."""

import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
VALIDATOR = REPO / "scripts/release/validate_receipt.py"
FIXTURE = Path(__file__).parent / "fixtures/release-receipts/complete-candidate.json"


class ReleaseReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "bundle"
        shutil.copytree(FIXTURE.parent / "bundle", self.bundle)
        self.receipt = json.loads(FIXTURE.read_text())

    def run_validator(self, receipt=None, *, candidate=True, expected=True, script=None):
        path = self.root / "receipt.json"
        path.write_text(json.dumps(self.receipt if receipt is None else receipt))
        return self.run_path(path, candidate=candidate, expected=expected, script=script)

    def run_path(self, path, *, candidate=True, expected=True, script=None):
        command = [sys.executable, str(script or VALIDATOR), str(path),
                   "--artifact-root", str(self.bundle)]
        if candidate:
            command.append("--require-candidate")
        if expected:
            source = json.loads(FIXTURE.read_text())["source"]
            command += ["--source-commit", source["commit"],
                        "--source-tree", source["tree"],
                        "--lock-sha256", source["lock"]["sha256"]]
        return subprocess.run(command, cwd=self.root, text=True, capture_output=True)

    def assert_rejected(self, receipt=None, reason=None, **kwargs):
        result = self.run_validator(receipt, **kwargs)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        if reason:
            self.assertIn(reason, result.stderr)

    def test_accepts_complete_candidate_receipt(self):
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_source_or_lock_mismatch(self):
        for field in ("commit", "tree", "lock"):
            with self.subTest(field=field):
                receipt = copy.deepcopy(self.receipt)
                if field == "lock":
                    receipt["source"]["lock"]["sha256"] = "0" * 64
                else:
                    receipt["source"][field] = "0" * 40
                self.assert_rejected(receipt, "mismatch")

    def test_rejects_missing_or_tampered_artifact(self):
        path = self.bundle / self.receipt["artifacts"]["comparison"]["path"]
        path.unlink()
        self.assert_rejected(reason="artifact")
        path.write_bytes(b"tampered")
        self.assert_rejected(reason="mismatch")

    def test_rejects_diagnostic_promotion_to_candidate(self):
        self.receipt["classification"] = "diagnostic"
        self.assert_rejected(reason="diagnostic")

    def test_rejects_incomplete_candidate_evidence(self):
        for completion in ({}, {"complete": False, "outcome": "passed"},
                           {"complete": True, "outcome": "incomplete"},
                           {"complete": True, "outcome": "failed"},
                           {"complete": 1, "outcome": "passed"}):
            with self.subTest(completion=completion):
                self.receipt["completion"] = completion
                self.assert_rejected(reason="completion")

    def test_rejects_artifact_path_escape(self):
        outside = self.root / "outside"
        outside.write_bytes(b"abc")
        for path in ("../outside", str(outside), "a/../../outside", "..\\outside"):
            with self.subTest(path=path):
                self.receipt["artifacts"]["comparison"]["path"] = path
                self.assert_rejected(reason="path")

    def create_symlink_or_skip(self, link, target):
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlink creation unavailable: {error}")

    def test_rejects_symlink_escape(self):
        outside = self.root / "outside"
        outside.write_bytes(b"abc")
        self.create_symlink_or_skip(self.bundle / "link", outside)
        self.receipt["artifacts"]["comparison"]["path"] = "link"
        self.assert_rejected(reason="symlink")

    def test_rejects_internal_symlink(self):
        target = self.receipt["artifacts"]["comparison"]["path"]
        self.create_symlink_or_skip(self.bundle / "internal-link", target)
        self.receipt["artifacts"]["comparison"]["path"] = "internal-link"
        self.assert_rejected(reason="symlink")

    def test_rejects_unknown_schema_or_receipt_kind(self):
        for field, value in (("schema_version", 2), ("schema_version", True),
                             ("kind", "invented"), ("classification", "release")):
            with self.subTest(field=field, value=value):
                receipt = copy.deepcopy(self.receipt)
                receipt[field] = value
                self.assert_rejected(receipt, reason=field)

    def test_candidate_requires_independent_source_binding(self):
        self.assert_rejected(reason="expected", expected=False)

    def test_diagnostic_can_record_failed_historical_evidence(self):
        self.receipt["classification"] = "diagnostic"
        self.receipt["completion"] = {"complete": False, "outcome": "failed"}
        result = self.run_validator(candidate=False, expected=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_all_artifact_roles_are_rehashed(self):
        for field in ("source", "binaries", "identities", "artifacts"):
            with self.subTest(field=field):
                receipt = copy.deepcopy(self.receipt)
                entry = {"path": "absent", "sha256": "0" * 64}
                if field == "source":
                    entry["sha256"] = receipt["source"]["lock"]["sha256"]
                    receipt[field]["lock"] = entry
                else:
                    receipt[field][next(iter(receipt[field]))] = entry
                self.assert_rejected(receipt, "artifact")

    def test_rejects_missing_binding_fields(self):
        for field in ("source", "toolchain", "binaries", "identities", "completion", "artifacts"):
            with self.subTest(field=field):
                receipt = copy.deepcopy(self.receipt)
                del receipt[field]
                self.assert_rejected(receipt, field)
        del self.receipt["identities"]["selection"]
        self.assert_rejected(reason="selection")

    def test_identity_nonapplicability_must_be_explicit(self):
        self.receipt["kind"] = "build"
        self.receipt["identities"]["provider"] = {"not_applicable": "No provider used for compilation"}
        self.assertEqual(self.run_validator().returncode, 0)
        self.receipt["identities"]["provider"] = {"not_applicable": ""}
        self.assert_rejected(reason="not_applicable")

    def test_rejects_malformed_and_ambiguous_json(self):
        path = self.root / "invalid.json"
        for content in ("{", "[]", '{"schema_version": 1, "schema_version": 2}', "NaN"):
            with self.subTest(content=content):
                path.write_text(content)
                result = self.run_path(path)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_rejects_unknown_fields_and_malformed_hashes(self):
        self.receipt["candidate"] = True
        self.assert_rejected(reason="unknown")
        del self.receipt["candidate"]
        self.receipt["artifacts"]["comparison"]["sha256"] = "not-a-hash"
        self.assert_rejected(reason="sha256")

    def test_rejects_nonportable_paths_and_directories(self):
        (self.bundle / "directory").mkdir()
        for path in ("", ".", "./evidence.txt", "a//b", "C:/evidence.txt",
                     "directory", "evidence.txt/"):
            with self.subTest(path=path):
                self.receipt["artifacts"]["comparison"]["path"] = path
                self.assert_rejected(reason="path")

    def test_rejects_windows_forbidden_characters_and_component_endings(self):
        names = [f"result{chr(code)}.json" for code in (*range(32), 127)]
        names += [f"result{char}.json" for char in '<>:"\\|?*']
        names += ["result.json.", "result.json ", "directory./result.json",
                  "directory /result.json"]
        for name in names:
            with self.subTest(path=name):
                self.receipt["artifacts"]["comparison"]["path"] = name
                self.assert_rejected(reason="portable")

    def test_rejects_windows_reserved_device_basenames(self):
        devices = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
        devices += [f"{prefix}{number}" for prefix in ("COM", "LPT")
                    for number in "123456789¹²³"]
        for device in devices:
            for name in (device, device.lower() + ".json", "nested/" + device + ".log"):
                with self.subTest(path=name):
                    self.receipt["artifacts"]["comparison"]["path"] = name
                    self.assert_rejected(reason="portable")

    def test_rejects_spaced_windows_device_basenames(self):
        for name in ("CON .json", "NUL  .txt", "LPT1 .log", "conin$ .txt"):
            with self.subTest(path=name):
                self.receipt["artifacts"]["comparison"]["path"] = name
                self.assert_rejected(reason="portable")

    def references(self):
        yield "source.lock", self.receipt["source"]["lock"]
        for group in ("binaries", "identities", "artifacts"):
            for role, reference in self.receipt[group].items():
                yield f"{group}.{role}", reference

    def test_rejects_case_collisions_across_all_artifact_roles(self):
        original = copy.deepcopy(self.receipt)
        for role, reference in list(self.references()):
            with self.subTest(role=role):
                name = reference["path"]
                alias = name.upper()
                self.assertNotEqual(name, alias)
                if not (self.bundle / alias).exists():
                    shutil.copyfile(self.bundle / name, self.bundle / alias)
                reference["path"] = alias
                self.receipt["artifacts"]["case-alias"] = {
                    "path": name, "sha256": reference["sha256"],
                }
                try:
                    self.assert_rejected(reason="collision")
                finally:
                    reference["path"] = name
                    del self.receipt["artifacts"]["case-alias"]
        self.assertEqual(self.receipt, original)

    def test_rejects_unicode_casefold_path_collisions(self):
        reference = self.receipt["artifacts"]["comparison"]
        for name in ("Straße.json", "STRASSE.JSON"):
            shutil.copyfile(self.bundle / reference["path"], self.bundle / name)
        self.receipt["artifacts"]["comparison"] = {
            "path": "Straße.json", "sha256": reference["sha256"],
        }
        self.receipt["artifacts"]["alias"] = {
            "path": "STRASSE.JSON", "sha256": reference["sha256"],
        }
        self.assert_rejected(reason="collision")

    def test_each_fixture_artifact_is_distinct_and_tampering_is_detected(self):
        references = list(self.references())
        self.assertEqual(len({ref["path"] for _, ref in references}), len(references))
        self.assertEqual(len({ref["sha256"] for _, ref in references}), len(references))
        for role, reference in references:
            with self.subTest(role=role):
                path = self.bundle / reference["path"]
                original = path.read_bytes()
                path.write_bytes(original + b"tampered")
                try:
                    self.assertTrue(path.is_file())
                    self.assert_rejected(reason=f"{role} artifact sha256 mismatch")
                finally:
                    path.write_bytes(original)

    def test_rejects_malformed_envelope_values_without_traceback(self):
        for field in self.receipt:
            for value in (None, [], 123):
                with self.subTest(field=field, value=value):
                    receipt = copy.deepcopy(self.receipt)
                    receipt[field] = value
                    self.assert_rejected(receipt)

    def test_rejects_inconsistent_completion_and_empty_artifacts(self):
        self.receipt["classification"] = "diagnostic"
        self.receipt["completion"] = {"complete": False, "outcome": "passed"}
        self.assert_rejected(reason="completion", candidate=False)
        self.receipt["completion"] = {"complete": True, "outcome": "incomplete"}
        self.assert_rejected(reason="completion", candidate=False)
        self.receipt["completion"] = {"complete": True, "outcome": "passed"}
        self.receipt["artifacts"] = {}
        self.assert_rejected(reason="artifacts", candidate=False)

    def test_validator_is_standalone(self):
        self.assertTrue(VALIDATOR.is_file(), "standalone validator has not been implemented")
        script = self.root / "validate_receipt.py"
        shutil.copyfile(VALIDATOR, script)
        result = self.run_validator(script=script)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

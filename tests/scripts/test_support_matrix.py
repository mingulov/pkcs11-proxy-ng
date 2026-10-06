"""Tests for scripts/release/support_matrix.py.

The generator turns a versioned ``pool-evidence/v1`` export into the
marked table of ``doc/release/beta-support-matrix.md``. Validation is
fail-closed: mixed-run merges, malformed identities, incomplete rows
without reasons, FAIL rows without dispositions, and mock providers
all refuse. stdlib only; no network, no private imports.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from release import support_matrix as sm  # noqa: E402


def make_row(**overrides):
    row = {"run_id": "pooled-1", "gate": "PASS", "complete": True,
           "regressions": 0, "known": 0, "improvements": 0,
           "both_nonpass": 0, "direct_only": 0, "proxy_only": 0,
           "incomplete": 0, "incomplete_reasons": [],
           "disposition": "", "evidence": ""}
    row.update(overrides)
    return row


def make_export(**overrides):
    export = {"format": "pool-evidence/v1", "run_id": "pooled-1",
              "candidate": {"commit": "a" * 40, "describe": "v0.2.3"},
              "framework": {"commit": "b" * 40},
              "generated_at": "2026-10-06T03:14:00Z",
              "evidence_root": "https://example.invalid/runs/pooled-1/",
              "providers": {"softhsm2": make_row()}}
    export.update(overrides)
    return export


class SupportMatrixValidationTests(unittest.TestCase):
    def test_valid_export_passes(self):
        self.assertEqual(sm.validate(make_export())["run_id"], "pooled-1")

    def test_empty_providers_skip_run_identity(self):
        export = sm.validate({"format": "pool-evidence/v1", "providers": {}})
        self.assertEqual(export["providers"], {})

    def test_rejections(self):
        bad_row = make_row(gate="PASS", complete=True)
        cases = {
            "not-an-object": ([], "export must be a JSON object"),
            "bad-format": (make_export(format="pool-evidence/v0"),
                           "format must be"),
            "providers-not-dict": (make_export(providers=[]),
                                   "providers must be an object"),
            "empty-run-id": (make_export(run_id=""),
                             "run_id must be a non-empty string"),
            "bad-candidate-commit": (
                make_export(candidate={"commit": "xyz"}),
                "candidate.commit must be"),
            "bad-framework-commit": (
                make_export(framework={"commit": "A" * 40}),
                "framework.commit must be"),
            "bad-generated-at": (make_export(generated_at="soon"),
                                 "generated_at must be"),
            "bad-provider-name": (
                make_export(providers={"Soft HSM": bad_row}),
                "invalid provider name"),
            "mock-provider": (
                make_export(providers={"pkcs11-mock": bad_row}),
                "mock is never parity evidence"),
            "row-not-dict": (make_export(providers={"softhsm2": []}),
                             "row must be an object"),
            "mixed-run-id": (
                make_export(providers={"softhsm2": make_row(run_id="other")}),
                "mixed-run merge"),
            "bad-gate": (make_export(providers={"softhsm2": make_row(gate="MAYBE")}),
                         "gate must be one of"),
            "complete-not-bool": (
                make_export(providers={"softhsm2": make_row(complete="yes")}),
                "complete must be a boolean"),
            "negative-count": (
                make_export(providers={"softhsm2": make_row(regressions=-1)}),
                "regressions must be >= 0"),
            "bool-count": (
                make_export(providers={"softhsm2": make_row(known=True)}),
                "known must be an integer"),
            "missing-count": (
                make_export(providers={"softhsm2": {
                    k: v for k, v in make_row().items()
                    if k != "improvements"}}),
                "improvements must be an integer"),
            "incomplete-without-reasons": (
                make_export(providers={"softhsm2": make_row(gate="INCOMPLETE")}),
                "incomplete rows need incomplete_reasons"),
            "partial-without-reasons": (
                make_export(providers={"softhsm2": make_row(complete=False)}),
                "incomplete rows need incomplete_reasons"),
            "fail-without-disposition": (
                make_export(providers={"softhsm2": make_row(gate="FAIL")}),
                "FAIL rows need a recorded disposition"),
            "evidence-not-string": (
                make_export(providers={"softhsm2": make_row(evidence=42)}),
                "evidence must be a string"),
        }
        for name, (export, needle) in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(sm.SupportMatrixError) as ctx:
                    sm.validate(export)
                self.assertIn(needle, str(ctx.exception))

    def test_load_evidence_refuses_malformed_json(self):
        tmp = Path(tempfile.mkdtemp(prefix="support-matrix-test-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        bad = tmp / "bad.json"
        bad.write_text("{nope", encoding="utf-8")
        with self.assertRaises(sm.SupportMatrixError):
            sm.load_evidence(bad)
        with self.assertRaises(sm.SupportMatrixError):
            sm.load_evidence(tmp / "missing.json")


class SupportMatrixRenderTests(unittest.TestCase):
    def test_empty_export_renders_placeholder(self):
        text = sm.render({"format": "pool-evidence/v1", "providers": {}})
        self.assertIn("No pooled comparison evidence recorded yet", text)

    def test_rows_render_sorted_with_provenance(self):
        export = make_export(providers={
            "nss": make_row(regressions=1, gate="FAIL",
                            disposition="triaged: provider drift",
                            evidence="nss-pooled/comparison.json"),
            "kryoptic": make_row(improvements=2)})
        text = sm.render(export)
        self.assertIn("run `pooled-1`", text)
        self.assertIn("v0.2.3", text)
        self.assertIn("lower bounds, not parity evidence", text)
        self.assertLess(text.index("kryoptic"), text.index("nss"))
        self.assertIn("| `kryoptic` | PASS | 0 | 0 | 2 |", text)
        self.assertIn("triaged: provider drift", text)
        self.assertIn("(https://example.invalid/runs/pooled-1/"
                      "nss-pooled/comparison.json)", text)

    def test_notes_fall_back_to_first_reason(self):
        export = make_export(providers={
            "tpm2": make_row(gate="INCOMPLETE",
                             incomplete_reasons=["shard 3 lost", "retry me"])})
        text = sm.render(export)
        self.assertIn("shard 3 lost", text)
        self.assertNotIn("retry me", text)

    def test_pipes_and_newlines_cannot_break_table(self):
        export = make_export(providers={
            "nss": make_row(gate="FAIL",
                            disposition="a|b\nc")})
        text = sm.render(export)
        for line in text.splitlines():
            if line.startswith("| `nss`"):
                self.assertIn("a\\|b c", line)


class SupportMatrixRegionTests(unittest.TestCase):
    def test_replace_region_swaps_only_marked_span(self):
        text = ("# Title\n\nbefore\n\n<!-- pool-evidence:begin -->\n"
                "OLD\n<!-- pool-evidence:end -->\nafter\n")
        updated = sm.replace_region(text, "NEW\n")
        self.assertIn("before\n\n<!-- pool-evidence:begin -->\nNEW\n"
                      "<!-- pool-evidence:end -->\nafter\n", updated)
        self.assertNotIn("OLD", updated)

    def test_replace_region_refuses_bad_markers(self):
        for text in ("no markers",
                     f"{sm.BEGIN}\nonly begin",
                     f"{sm.BEGIN}\n{sm.BEGIN}\nx\n{sm.END}",
                     f"{sm.END}\n{sm.BEGIN}\n"):
            with self.subTest(text=text):
                with self.assertRaises(sm.SupportMatrixError):
                    sm.replace_region(text, "NEW\n")


class SupportMatrixCliTests(unittest.TestCase):
    def stage(self, export):
        tmp = Path(tempfile.mkdtemp(prefix="support-matrix-cli-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        evidence = tmp / "evidence.json"
        evidence.write_text(json.dumps(export), encoding="utf-8")
        matrix = tmp / "matrix.md"
        matrix.write_text("# M\n\n<!-- pool-evidence:begin -->\n"
                          "STALE\n<!-- pool-evidence:end -->\n",
                          encoding="utf-8")
        return evidence, matrix

    def test_check_reports_stale_then_regenerates(self):
        evidence, matrix = self.stage(make_export())
        code = sm.main(["--evidence", str(evidence),
                        "--matrix", str(matrix), "--check"])
        self.assertEqual(code, 1)
        code = sm.main(["--evidence", str(evidence),
                        "--matrix", str(matrix)])
        self.assertEqual(code, 0)
        self.assertIn("softhsm2", matrix.read_text(encoding="utf-8"))
        code = sm.main(["--evidence", str(evidence),
                        "--matrix", str(matrix), "--check"])
        self.assertEqual(code, 0)

    def test_invalid_export_fails(self):
        evidence, matrix = self.stage(make_export(format="nope"))
        code = sm.main(["--evidence", str(evidence),
                        "--matrix", str(matrix), "--check"])
        self.assertEqual(code, 1)

    def test_checked_in_matrix_matches_export(self):
        # The tracked table must equal a fresh render of the
        # tracked export; regeneration PRs update both together.
        self.assertEqual(sm.main(["--check"]), 0)


if __name__ == "__main__":
    unittest.main()

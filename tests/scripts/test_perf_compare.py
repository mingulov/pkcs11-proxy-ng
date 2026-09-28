"""Comparable workload receipts and honest summaries (perf T1)."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from perf.compare import (  # noqa: E402
    COMPARABLE,
    DIAGNOSTIC_ONLY,
    compare_pair,
)


def make_manifest(mode="direct", **overrides):
    manifest = {
        "receipt_version": 1,
        "source_head": "abc123def",
        "dirty_patch_hash": None,
        "clean": True,
        "profile": "release",
        "build_id": f"{mode}-build-1",
        "target_abi": "x86_64-unknown-linux-gnu",
        "provider": {
            "module": "libsofthsm2.so",
            "image": "docker-test-softhsm2:latest",
            "config_fingerprint": "token-init-v1",
        },
        "workload": {"revision": "panel-v3", "corpus_hash": "corpus-9f"},
        "mode": mode,
        "host": {"kernel": "6.8", "cpu": "x86_64-16"},
        "transport": "uds" if mode == "direct" else "uds",
        "warmup": 100,
        "concurrency": 1,
    }
    manifest.update(overrides)
    return manifest


def make_sample(
    run_id="r1",
    attempt_id="a1",
    sample_id="s1",
    workload="sign-reused-key",
    operation="C_Sign",
    mode="direct",
    duration_ns=1_000_000,
    outcome="success",
    rv=0,
    native_call_count=1,
    censored=False,
):
    return {
        "run_id": run_id,
        "attempt_id": attempt_id,
        "sample_id": sample_id,
        "workload": workload,
        "operation": operation,
        "mode": mode,
        "duration_ns": duration_ns,
        "outcome": outcome,
        "rv": rv,
        "native_call_count": native_call_count,
        "censored": censored,
    }


def matching_pair(n=5, base_ns=1_000_000, step_ns=100_000):
    """Two eligible legs with deterministic durations 1.0ms, 1.1ms, ..."""
    direct = [
        make_sample(sample_id=f"s{i}", duration_ns=base_ns + i * step_ns)
        for i in range(n)
    ]
    proxied = [
        make_sample(
            run_id="r2",
            sample_id=f"s{i}",
            mode="proxied",
            duration_ns=base_ns + i * step_ns,
        )
        for i in range(n)
    ]
    return direct, proxied


class EligibilityTests(unittest.TestCase):
    def test_matching_completed_pair_is_comparable(self):
        direct, proxied = matching_pair()
        result = compare_pair(
            make_manifest("direct"), make_manifest("proxied"), direct, proxied
        )
        self.assertEqual(result["eligibility"], COMPARABLE)
        self.assertEqual(result["reasons"], [])
        self.assertIsNotNone(result["latency"])
        self.assertIsNotNone(result["throughput"])

    def test_known_median_and_counts(self):
        direct, proxied = matching_pair(n=5)
        result = compare_pair(
            make_manifest("direct"), make_manifest("proxied"), direct, proxied
        )
        # durations 1.0..1.4ms; nearest-rank p50 of 5 values is the 3rd.
        self.assertEqual(result["latency"]["direct"]["p50_ns"], 1_200_000)
        self.assertEqual(result["latency"]["proxied"]["p50_ns"], 1_200_000)
        self.assertEqual(result["latency"]["direct"]["n"], 5)
        self.assertEqual(result["latency"]["median_delta_ns"], 0)
        self.assertEqual(result["counts"]["direct"]["success"], 5)
        self.assertEqual(result["counts"]["proxied"]["success"], 5)
        self.assertEqual(result["throughput"]["direct"]["completed"], 5)
        self.assertEqual(result["native_calls"], {"direct": 5, "proxied": 5})

    def test_version_mismatch_is_diagnostic(self):
        direct, proxied = matching_pair()
        result = compare_pair(
            make_manifest("direct"),
            make_manifest("proxied", receipt_version=2),
            direct,
            proxied,
        )
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        self.assertTrue(any("version" in r for r in result["reasons"]))

    def test_missing_provider_identity_is_diagnostic(self):
        direct, proxied = matching_pair()
        manifest = make_manifest("proxied")
        del manifest["provider"]
        result = compare_pair(make_manifest("direct"), manifest, direct, proxied)
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        self.assertTrue(any("provider" in r for r in result["reasons"]))

    def test_changed_provider_identity_is_diagnostic(self):
        direct, proxied = matching_pair()
        manifest = make_manifest("proxied")
        manifest["provider"] = dict(
            manifest["provider"], image="docker-test-nss:latest"
        )
        result = compare_pair(make_manifest("direct"), manifest, direct, proxied)
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        self.assertTrue(any("provider" in r for r in result["reasons"]))

    def test_missing_workload_identity_is_diagnostic(self):
        direct, proxied = matching_pair()
        manifest = make_manifest("direct")
        del manifest["workload"]["corpus_hash"]
        result = compare_pair(manifest, make_manifest("proxied"), direct, proxied)
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        self.assertTrue(any("workload" in r for r in result["reasons"]))

    def test_changed_workload_revision_is_diagnostic(self):
        direct, proxied = matching_pair()
        manifest = make_manifest("proxied")
        manifest["workload"] = dict(manifest["workload"], revision="panel-v4")
        result = compare_pair(make_manifest("direct"), manifest, direct, proxied)
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        self.assertTrue(any("workload" in r for r in result["reasons"]))

    def test_wrong_mode_slots_are_diagnostic(self):
        direct, proxied = matching_pair()
        result = compare_pair(
            make_manifest("direct"),
            make_manifest("direct"),
            direct,
            proxied,
        )
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        self.assertTrue(any("mode" in r for r in result["reasons"]))

    def test_different_operation_sequences_are_diagnostic(self):
        direct, proxied = matching_pair()
        proxied[2]["operation"] = "C_Verify"
        result = compare_pair(
            make_manifest("direct"), make_manifest("proxied"), direct, proxied
        )
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        self.assertTrue(any("sequence" in r for r in result["reasons"]))

    def test_different_outcome_mix_is_diagnostic_and_retained(self):
        direct, proxied = matching_pair()
        proxied[1]["outcome"] = "timeout"
        result = compare_pair(
            make_manifest("direct"), make_manifest("proxied"), direct, proxied
        )
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        # Mixed evidence is retained in counts, never silently filtered.
        self.assertEqual(result["counts"]["proxied"]["timeout"], 1)
        self.assertEqual(result["counts"]["proxied"]["success"], 4)
        self.assertEqual(result["counts"]["direct"]["success"], 5)
        self.assertIsNone(result["latency"])
        self.assertIsNone(result["throughput"])

    def test_fewer_completions_visible_not_speedup(self):
        direct, proxied = matching_pair()
        for sample in proxied[3:]:
            sample["outcome"] = "error"
        result = compare_pair(
            make_manifest("direct"), make_manifest("proxied"), direct, proxied
        )
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        self.assertEqual(result["counts"]["direct"]["success"], 5)
        self.assertEqual(result["counts"]["proxied"]["success"], 3)
        self.assertEqual(result["counts"]["proxied"]["error"], 2)
        self.assertIsNone(result["latency"])

    def test_duplicate_sample_identity_is_diagnostic(self):
        direct, proxied = matching_pair()
        direct.append(dict(direct[0]))
        result = compare_pair(
            make_manifest("direct"), make_manifest("proxied"), direct, proxied
        )
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        self.assertTrue(any("duplicate" in r for r in result["reasons"]))

    def test_missing_duration_is_diagnostic(self):
        direct, proxied = matching_pair()
        direct[0]["duration_ns"] = None
        result = compare_pair(
            make_manifest("direct"), make_manifest("proxied"), direct, proxied
        )
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        self.assertTrue(any("duration" in r for r in result["reasons"]))

    def test_nonpositive_duration_is_diagnostic(self):
        direct, proxied = matching_pair()
        proxied[4]["duration_ns"] = 0
        result = compare_pair(
            make_manifest("direct"), make_manifest("proxied"), direct, proxied
        )
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        self.assertTrue(any("duration" in r for r in result["reasons"]))

    def test_unfinished_attempt_is_diagnostic(self):
        direct, proxied = matching_pair()
        direct[2]["outcome"] = "unfinished"
        result = compare_pair(
            make_manifest("direct"), make_manifest("proxied"), direct, proxied
        )
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        self.assertTrue(any("unfinished" in r for r in result["reasons"]))

    def test_censored_execution_is_diagnostic(self):
        direct, proxied = matching_pair()
        proxied[0]["censored"] = True
        result = compare_pair(
            make_manifest("direct"), make_manifest("proxied"), direct, proxied
        )
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        self.assertTrue(any("censor" in r for r in result["reasons"]))

    def test_ineligible_pair_omits_latency_throughput(self):
        direct, proxied = matching_pair()
        direct, proxied = direct[:3], proxied  # different work sequences
        result = compare_pair(
            make_manifest("direct"), make_manifest("proxied"), direct, proxied
        )
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        self.assertIsNone(result["latency"])
        self.assertIsNone(result["throughput"])
        # Individual durations remain available as diagnostic evidence.
        self.assertEqual(result["counts"]["direct"]["total"], 3)
        self.assertEqual(result["counts"]["proxied"]["total"], 5)

    def test_sample_mode_must_match_its_manifest(self):
        direct, proxied = matching_pair()
        direct[1]["mode"] = "proxied"
        result = compare_pair(
            make_manifest("direct"), make_manifest("proxied"), direct, proxied
        )
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        self.assertTrue(any("mode" in r for r in result["reasons"]))

    def test_mixed_runs_in_one_leg_are_diagnostic(self):
        direct, proxied = matching_pair()
        direct[4]["run_id"] = "rX"
        result = compare_pair(
            make_manifest("direct"), make_manifest("proxied"), direct, proxied
        )
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        self.assertTrue(any("run_id" in r for r in result["reasons"]))


class ProxyVsProxyTests(unittest.TestCase):
    def test_matching_proxy_pair_is_comparable(self):
        direct, proxied = matching_pair()
        for sample in direct:
            sample["mode"] = "proxied"
        result = compare_pair(
            make_manifest("proxied", build_id="proxy-baseline-7"),
            make_manifest("proxied", build_id="proxy-candidate-8"),
            direct,
            proxied,
        )
        self.assertEqual(result["eligibility"], COMPARABLE)

    def test_indistinct_proxy_builds_are_diagnostic(self):
        direct, proxied = matching_pair()
        for sample in direct:
            sample["mode"] = "proxied"
        result = compare_pair(
            make_manifest("proxied", build_id="proxy-same"),
            make_manifest("proxied", build_id="proxy-same"),
            direct,
            proxied,
        )
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        self.assertTrue(any("build" in r for r in result["reasons"]))


if __name__ == "__main__":
    unittest.main()

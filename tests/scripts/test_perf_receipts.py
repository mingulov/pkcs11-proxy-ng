"""Pin the bench T1 receipt schema consumed by perf.compare (perf T2).

These fixtures mirror the exact shape emitted by
crates/server/benches/common/receipts.rs (see scripts/perf/README.md).
If the emitter changes shape, update both sides together: fixtures here
prove the comparator still reads the contract, and live bench runs prove
the emitter still writes it.
"""

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


def emitter_manifest(build_tag):
    return {
        "receipt_version": 1,
        "source_head": "deadbeef" * 5,
        "dirty_patch_hash": None,
        "clean": True,
        "profile": "release",
        "build_id": f"release-deadbeef{build_tag}-{build_tag}",
        "target_abi": "x86_64-linux",
        "provider": {
            "module": "mock",
            "image": "in-process-mock",
            "config_fingerprint": "mock-default",
        },
        "workload": {
            "revision": "sign-pair-v1",
            "corpus_hash": "payload-256B-0xAB-fixed",
        },
        "mode": "proxied",
        "host": {"arch": "x86_64", "os": "linux"},
        "transport": "tcp-loopback-insecure",
        "warmup": 100,
        "concurrency": 1,
    }


def emitter_sample(run_id, index, duration_ns, outcome="success", rv=0):
    return {
        "run_id": run_id,
        "attempt_id": "a0",
        "sample_id": f"s{index}",
        "workload": "sign-pair",
        "operation": "SignInit+Sign",
        "mode": "proxied",
        "duration_ns": duration_ns,
        "outcome": outcome,
        "rv": rv,
        "native_call_count": None,
        "censored": False,
    }


class EmitterContractTests(unittest.TestCase):
    def test_emitter_shaped_pair_is_comparable(self):
        base = emitter_manifest("baseline")
        cand = emitter_manifest("candidate")
        # Distinct builds (same source, different tags) is the honest
        # baseline-proxy vs candidate-proxy shape for mock-backed legs.
        self.assertNotEqual(base["build_id"], cand["build_id"])
        direct = [emitter_sample("r1", i, 100_000 + i * 10_000) for i in range(3)]
        proxied = [emitter_sample("r2", i, 110_000 + i * 10_000) for i in range(3)]
        result = compare_pair(base, cand, direct, proxied)
        self.assertEqual(result["eligibility"], COMPARABLE)
        self.assertEqual(result["latency"]["direct"]["p50_ns"], 110_000)
        self.assertEqual(result["latency"]["proxied"]["p50_ns"], 120_000)
        self.assertEqual(result["latency"]["median_delta_ns"], 10_000)
        self.assertEqual(result["native_calls"], {"direct": None, "proxied": None})

    def test_emitter_error_sample_stays_diagnostic(self):
        base = emitter_manifest("baseline")
        cand = emitter_manifest("candidate")
        direct = [emitter_sample("r1", i, 100_000) for i in range(3)]
        proxied = [emitter_sample("r2", i, 100_000) for i in range(3)]
        proxied[2] = emitter_sample("r2", 2, 95_000, outcome="error", rv=0x13)
        result = compare_pair(base, cand, direct, proxied)
        self.assertEqual(result["eligibility"], DIAGNOSTIC_ONLY)
        self.assertEqual(result["counts"]["proxied"]["error"], 1)
        self.assertIsNone(result["latency"])


if __name__ == "__main__":
    unittest.main()

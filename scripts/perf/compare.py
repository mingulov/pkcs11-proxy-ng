"""Comparable workload receipts and honest summaries (perf T1).

``compare_pair`` decides whether two benchmark legs (direct vs proxied, or
baseline-proxy vs candidate-proxy) form a COMPARABLE pair or are
DIAGNOSTIC_ONLY. Latency/throughput comparisons are emitted only for an
eligible pair; individual durations always remain available as diagnostic
evidence via ``counts``. Mixed success/failure evidence is retained in
``counts`` and forces DIAGNOSTIC_ONLY -- it is never silently filtered
into a successful performance comparison.
"""

import math

COMPARABLE = "COMPARABLE"
DIAGNOSTIC_ONLY = "DIAGNOSTIC_ONLY"

#: Outcomes that finish an attempt. Anything else (notably ``unfinished``)
#: makes the pair diagnostic-only.
FINISHED_OUTCOMES = frozenset({"success", "timeout", "error", "unknown"})

#: Sample keys every record must carry. ``rv`` and ``native_call_count`` may
#: be None (recorded as unavailable, never zero-filled).
REQUIRED_SAMPLE_KEYS = (
    "run_id",
    "attempt_id",
    "sample_id",
    "workload",
    "operation",
    "mode",
    "duration_ns",
    "outcome",
)

#: Manifest identity dimensions that must match within a pair. A missing key
#: is not a wildcard: it makes the pair diagnostic-only.
PROVIDER_IDENTITY_KEYS = ("module", "image", "config_fingerprint")
WORKLOAD_IDENTITY_KEYS = ("revision", "corpus_hash")


def _percentile(sorted_values, percent):
    """Nearest-rank percentile over an ascending list (None when empty)."""
    if not sorted_values:
        return None
    rank = int(math.ceil(percent / 100.0 * len(sorted_values)))
    return sorted_values[max(0, min(rank - 1, len(sorted_values) - 1))]


def _leg_summary(samples):
    """Latency/throughput over the successful samples of one leg."""
    durations = sorted(
        s["duration_ns"] for s in samples if s.get("outcome") == "success"
    )
    busy_ns = sum(durations)
    per_second = (len(durations) / (busy_ns / 1e9)) if busy_ns > 0 else None
    return {
        "p50_ns": _percentile(durations, 50),
        "p95_ns": _percentile(durations, 95),
        "p99_ns": _percentile(durations, 99),
        "min_ns": durations[0] if durations else None,
        "max_ns": durations[-1] if durations else None,
        "n": len(durations),
        "completed": len(durations),
        "busy_ns": busy_ns,
        "per_busy_second": per_second,
    }


def _count_outcomes(samples):
    counts = {
        "success": 0,
        "timeout": 0,
        "error": 0,
        "unknown": 0,
        "unfinished": 0,
        "censored": 0,
        "total": len(samples),
    }
    for sample in samples:
        outcome = sample.get("outcome")
        if outcome in counts:
            counts[outcome] += 1
        if sample.get("censored"):
            counts["censored"] += 1
    return counts


def _sum_native_calls(samples):
    """Summed native_call_count, or None when any value is unavailable."""
    total = 0
    for sample in samples:
        value = sample.get("native_call_count")
        if value is None:
            return None
        total += value
    return total


def _check_manifests(direct_manifest, proxied_manifest, reasons):
    for label, manifest in (("direct", direct_manifest), ("proxied", proxied_manifest)):
        if not isinstance(manifest, dict):
            reasons.append(f"{label} manifest is not a mapping")
    if reasons:
        return
    direct_version = direct_manifest.get("receipt_version")
    proxied_version = proxied_manifest.get("receipt_version")
    if direct_version is None or proxied_version is None:
        reasons.append("missing receipt_version identity")
    elif direct_version != proxied_version:
        reasons.append(
            f"receipt_version differs: {direct_version!r} vs {proxied_version!r}"
        )
    for section, keys in (
        ("provider", PROVIDER_IDENTITY_KEYS),
        ("workload", WORKLOAD_IDENTITY_KEYS),
    ):
        direct_section = direct_manifest.get(section)
        proxied_section = proxied_manifest.get(section)
        if not isinstance(direct_section, dict) or not isinstance(
            proxied_section, dict
        ):
            reasons.append(f"missing {section} identity")
            continue
        for key in keys:
            if key not in direct_section or key not in proxied_section:
                reasons.append(f"missing {section} identity key {key!r}")
            elif direct_section[key] != proxied_section[key]:
                reasons.append(
                    f"{section} identity differs at {key!r}: "
                    f"{direct_section[key]!r} vs {proxied_section[key]!r}"
                )
    direct_mode = direct_manifest.get("mode")
    proxied_mode = proxied_manifest.get("mode")
    if direct_mode not in ("direct", "proxied"):
        reasons.append(f"direct leg has unexpected mode {direct_mode!r}")
    if proxied_mode != "proxied":
        reasons.append(f"proxied leg has unexpected mode {proxied_mode!r}")
    if direct_mode == "proxied" and proxied_mode == "proxied":
        direct_build = direct_manifest.get("build_id")
        proxied_build = proxied_manifest.get("build_id")
        if direct_build is None or proxied_build is None:
            reasons.append("proxy-vs-proxy pair needs distinct build_id values")
        elif direct_build == proxied_build:
            reasons.append(
                f"proxy-vs-proxy pair shares build_id {direct_build!r}; "
                "baseline and candidate builds must be distinct"
            )


def _check_samples(label, expected_mode, samples, reasons):
    if not isinstance(samples, list):
        reasons.append(f"{label} samples are not a list")
        return
    seen_identities = set()
    run_ids = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            reasons.append(f"{label} sample {index} is not a mapping")
            continue
        for key in REQUIRED_SAMPLE_KEYS:
            if key not in sample:
                reasons.append(f"{label} sample {index} misses {key!r}")
        identity = (
            sample.get("run_id"),
            sample.get("attempt_id"),
            sample.get("sample_id"),
        )
        if identity in seen_identities:
            reasons.append(f"{label} has duplicate sample identity {identity!r}")
        seen_identities.add(identity)
        run_ids.add(sample.get("run_id"))
        if sample.get("mode") != expected_mode:
            reasons.append(
                f"{label} sample {index} has mode {sample.get('mode')!r}, "
                f"expected {expected_mode!r}"
            )
        duration = sample.get("duration_ns")
        if duration is None:
            reasons.append(f"{label} sample {index} has missing duration")
        elif isinstance(duration, bool) or not isinstance(duration, (int, float)):
            reasons.append(f"{label} sample {index} has non-numeric duration")
        elif duration <= 0:
            reasons.append(f"{label} sample {index} has nonpositive duration")
        if sample.get("outcome") not in FINISHED_OUTCOMES:
            reasons.append(
                f"{label} sample {index} has unfinished outcome "
                f"{sample.get('outcome')!r}"
            )
        if sample.get("censored"):
            reasons.append(f"{label} sample {index} is censored")
    if len(run_ids) > 1:
        reasons.append(
            f"{label} mixes run_id values {sorted(run_ids, key=repr)}; "
            "one pair compares one run per leg"
        )


def _check_sequences(direct_samples, proxied_samples, reasons):
    if not isinstance(direct_samples, list) or not isinstance(proxied_samples, list):
        return
    direct_work = [
        (s.get("workload"), s.get("operation"))
        for s in direct_samples
        if isinstance(s, dict)
    ]
    proxied_work = [
        (s.get("workload"), s.get("operation"))
        for s in proxied_samples
        if isinstance(s, dict)
    ]
    if direct_work != proxied_work:
        reasons.append(
            f"work sequences differ ({len(direct_work)} direct vs "
            f"{len(proxied_work)} proxied operations)"
        )
    direct_outcomes = [
        s.get("outcome") for s in direct_samples if isinstance(s, dict)
    ]
    proxied_outcomes = [
        s.get("outcome") for s in proxied_samples if isinstance(s, dict)
    ]
    if direct_outcomes != proxied_outcomes:
        reasons.append(
            "outcome sequences differ; mixed success/failure evidence is "
            "retained in counts and the pair stays diagnostic-only"
        )


def compare_pair(direct_manifest, proxied_manifest, direct_samples, proxied_samples):
    """Compare one direct leg against one proxied leg.

    Returns a dict with ``eligibility`` (``COMPARABLE`` or
    ``DIAGNOSTIC_ONLY``), ``reasons``, ``counts``, ``latency``,
    ``throughput``, and ``native_calls``. ``latency`` and ``throughput``
    are None for an ineligible pair: no per-call quotient is emitted for
    pairs whose identity, population, or completion evidence disagrees.
    """
    reasons = []
    _check_manifests(direct_manifest, proxied_manifest, reasons)
    direct_mode = (
        direct_manifest.get("mode")
        if isinstance(direct_manifest, dict)
        else "direct"
    )
    _check_samples("direct", direct_mode, direct_samples, reasons)
    _check_samples("proxied", "proxied", proxied_samples, reasons)
    _check_sequences(direct_samples, proxied_samples, reasons)

    counts = {
        "direct": _count_outcomes(
            direct_samples if isinstance(direct_samples, list) else []
        ),
        "proxied": _count_outcomes(
            proxied_samples if isinstance(proxied_samples, list) else []
        ),
    }
    native_calls = {
        "direct": _sum_native_calls(
            direct_samples if isinstance(direct_samples, list) else []
        ),
        "proxied": _sum_native_calls(
            proxied_samples if isinstance(proxied_samples, list) else []
        ),
    }
    if reasons:
        return {
            "eligibility": DIAGNOSTIC_ONLY,
            "reasons": reasons,
            "counts": counts,
            "latency": None,
            "throughput": None,
            "native_calls": native_calls,
        }
    direct_leg = _leg_summary(direct_samples)
    proxied_leg = _leg_summary(proxied_samples)
    direct_p50 = direct_leg["p50_ns"]
    proxied_p50 = proxied_leg["p50_ns"]
    return {
        "eligibility": COMPARABLE,
        "reasons": [],
        "counts": counts,
        "latency": {
            "direct": {
                key: direct_leg[key]
                for key in ("p50_ns", "p95_ns", "p99_ns", "min_ns", "max_ns", "n")
            },
            "proxied": {
                key: proxied_leg[key]
                for key in ("p50_ns", "p95_ns", "p99_ns", "min_ns", "max_ns", "n")
            },
            "median_delta_ns": (
                None
                if direct_p50 is None or proxied_p50 is None
                else proxied_p50 - direct_p50
            ),
            "population": "successful samples only",
        },
        "throughput": {
            "direct": {
                key: direct_leg[key]
                for key in ("completed", "busy_ns", "per_busy_second")
            },
            "proxied": {
                key: proxied_leg[key]
                for key in ("completed", "busy_ns", "per_busy_second")
            },
            "definition": (
                "successful completions per summed successful-sample "
                "busy time; fewer completions must not read as a speedup"
            ),
        },
        "native_calls": native_calls,
    }

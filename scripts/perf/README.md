# Perf evidence tooling (T1–T5)

Proxy-owned benchmark experiments: comparable workload receipts, honest
summaries, and the soak / cold-start harnesses. This directory consumes
pkcs11-check artifacts read-only; generic framework reporting stays in
the framework repository.

## Run receipts (manifests)

Every benchmark leg writes one manifest dict. Identity dimensions must
match within a compared pair; a missing identity key is never a wildcard.

Required keys: `receipt_version`, `source_head`, `dirty_patch_hash`
(`None` only for a clean tree — record `clean: true` alongside),
`profile` (`release` for any quoted number), `build_id` (opaque build
identity; baseline-proxy and candidate-proxy builds must differ),
`target_abi`, `provider` (`module`, `image`, `config_fingerprint`),
`workload` (`revision`, `corpus_hash`), `mode` (`direct` or `proxied`).

Recommended context (carried, not gated): binary hashes, host/kernel/CPU
limits, topology, transport/auth/audit settings, warmup, concurrency,
deadline settings, token/session initialization, attempt IDs.

## Samples

One record per measured operation:

`run_id`, `attempt_id`, `sample_id`, `workload`, `operation`, `mode`,
`duration_ns` (monotonic clock, positive), `outcome` (`success`,
`timeout`, `error`, `unknown`, or `unfinished`), `rv`, `native_call_count`,
`censored` (bool).

Record missing values as unavailable (`None`), never zero. Equal
aggregate `native_call_count` values do not prove equal work.

## Comparator (`compare.py`)

`compare_pair(direct_manifest, proxied_manifest, direct_samples,
proxied_samples)` returns `eligibility` (`COMPARABLE` or
`DIAGNOSTIC_ONLY`), `reasons`, `counts`, `latency`, `throughput`, and
`native_calls`.

A pair is comparable only when versions match, provider/workload
identity matches, modes sit in the expected slots (proxy-vs-proxy needs
distinct `build_id` values), sample identities are unique, every sample
carries a positive duration, no attempt is unfinished or censored, and
the ordered work and outcome sequences agree. Anything else yields
`DIAGNOSTIC_ONLY` with explicit reasons, and `latency`/`throughput` are
withheld (`None`): no per-call quotient is emitted for pairs whose
identity, population, or completion evidence disagrees.

For eligible pairs, `latency` reports successful-operation p50/p95/p99
(nearest-rank), min/max, and the median delta; `throughput` reports
successful completions per summed successful-sample busy second.
`counts` always retains the full success/failure mix, so fewer
completions can never read as a speedup, and no retry subset is ever
cherry-picked as the population.

## Degraded operation (T3)

Timeout and cancellation follow one rule: a timed-out call reports
`CKR_FUNCTION_FAILED` with an unknown native outcome, exactly one native
attempt, and no replay. Local refusals happen before native entry; healthy
calls proceed alongside stalled ones. The `t3_*` tests in
`crates/server/tests/concurrency_and_recovery_test.rs` pin this behavior
against a mock backend with observed native-entry counts; shutdown and
restart lifecycle cases live in `shutdown_lifetime_test.rs`.

## Harnesses

- `soak.sh` — sustained-load soak driver (T2/T3).
- `cold_start_storm.sh` — cold connect/init storm driver (T2/T3).
- `../release/` packaging and the benches under
  `crates/server/benches/` emit T1 receipts/samples for their runs.

## Latency decomposition recipe (T4)

`proxy_latency_histogram` runs the same SignInit+Sign sequence in two
modes: `--direct` drives MockBackend in-process (no gRPC), default
drives it through a loopback daemon. Emit one T1 receipt per mode with
the same `T1_BUILD_TAG` and compare the pair with `compare_pair` —
a clean pair is `COMPARABLE` and the median delta is the proxy
overhead for that workload (measured: direct p50 331 ns vs proxied
p50 116.7 µs, n=200 each).

Measured breakdown of the 121 µs proxied sign-pair p50 (MockBackend,
loopback, release; host-dependent, re-run before quoting):

| Leg | p50 | Share |
| --- | --- | --- |
| Proxied pair, TCP loopback | 121 µs | 100% |
| Proxied pair, unix socket | 86 µs | 71% |
| Single cheap RPC, TCP | 57 µs | 47% (~half the pair: fixed per-RPC cost dominates) |
| Single cheap RPC, unix | 43 µs | — |
| In-process service call (dispatch + backend) | 0.4 µs | <1% |
| Prost codec (encode+decode ×2) | 0.15 µs | <1% |
| Direct backend pair | <1 µs | <1% |

Ranked outcome: proxy code is ~0.5% of per-RPC latency, so handler /
codec micro-optimizations are deferred (ceiling <1%, below the ±5%
A/A noise bar). The one adopted improvement is operational, not code:
co-located consumer+daemon deployments should use the unix-socket
listener, which cuts the sign-pair p50 by ~29% with no code change
(see the runbook's co-located transport note). Combining Init+op
pairs into single RPCs would cut per-RPC fixed cost further but is a
protocol change — deferred, not designed here.

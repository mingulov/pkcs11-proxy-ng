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

## Harness completion contracts (Q09)

`cold_start_storm.sh` owns exactly the child processes it starts
(setup steps, N workload processes, one sampler), joins each one under
a monotonic wall bound, and cleans up on EXIT/INT/TERM. There is no
unqualified `wait`; completion is file-observable (done-files and row
files) so an unverifiable process state never burns a whole timeout.

- The verdict is `PASS` or `FAIL_*` with explicit `reasons`; every
  started run writes a valid versioned JSON summary
  (`cold-start-summary/1`, atomically) for success and failure records
  alike. Signals write a terminal `FAIL_INTERRUPTED` record naming the
  signal and keep their 128+signal exit status.
- Verdict precedence is `FAIL_WORKLOAD` over `FAIL_CLEANUP` over
  `FAIL_SAMPLER`: a failed workload outranks everything, unverifiable
  cleanup outranks bad measurements.
- Missing/unusable measurements render as `null`, never zero. A run
  with no usable RSS or CPU dimension, no completed work, an unfinished
  workload, malformed sampler rows, or unresolved cleanup is
  non-success with a nonzero exit.
- Exit status: 0 on `PASS`; 1 on a `FAIL_*` verdict; 2 on usage/setup
  errors (nothing ran, no summary); 128+signal on signals.
- A process that is present but unreadable is unknown, never gone:
  while any `/proc` read genuinely fails, tree cleanup cannot be
  verified and the verdict fails closed to `FAIL_CLEANUP` with the
  unverified PIDs in `unresolved_pids`.
- Owned host jobs run in per-job process groups so blind cleanup
  still reaches unenumerated descendants (group kill).
- Workload shims run in an exclusively owned disposable run container
  (one per run, recorded in `run_container`, carrying a
  `coldstart-run-id` ownership label). After host joins, the run
  container is removed authoritatively (`docker rm -f`), which stops
  every shim inside regardless of host privileges or /proc
  readability. An unconfirmed removal fails closed to `FAIL_CLEANUP`
  ("container-side termination could not be verified"). A creation
  whose acknowledgement never arrives is reconciled before cleanup
  claims anything: the run is refused (exit 2) or interrupted, and the
  exit trap verifies the ownership label before removing — absent
  means nothing was created, anything unverifiable is left in place
  and fails closed. The harness never host-signals container processes
  and never selects processes by command text, so foreign processes
  are unreachable by design.
- A failed storm-clock read fails closed: before any work starts the
  run is refused (exit 2); once the storm has started, the run ends
  `FAIL_WORKLOAD` with null elapsed and an explicit reason.
- Wall-time quantiles use nearest-rank over successful rows only.
  `workload_contract` records whether the run is inside the
  single-logical-client support contract (`N=1`) or diagnostic-only.
  The effective numeric bounds are echoed in `bounds`.
- All inputs are canonicalized (explicit base 10, no octal holes) and
  range-checked before any work starts: N is 1–100000, timeouts and
  grace are 0–31536000 s, startup sleep and sample interval are
  0–3600 s. Summary numerics are canonical decimal (no leading zeros);
  corrupt sampler fields empty exactly their field, and sampler rows
  that fail the strict shape check count as `malformed_samples`.
- The `COLD_START_*` environment overrides exist so the harness itself
  can be tested deterministically; defaults are the production values.
  `COLD_START_STAT_READER` (default `cat`) selects the command used to
  read `/proc` state and exists only for failure injection in tests.
  `COLD_START_CLOCK_CALLER` names each boundary clock call for the
  test-double clock (failure injection and deterministic durations).
  See `tests/scripts/test_perf_harnesses.py`.

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

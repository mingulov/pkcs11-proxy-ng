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

## Soak completion contract (Q10)

`soak.sh` drives sustained C_Sign load for `DURATION` seconds at `RPS`
and samples daemon RSS + open FDs around it. The load worker is an
owned foreground `docker exec` the harness joins under a monotonic
bound before reading its result: no detached work, no fixed cross-run
result filename, and no worker/controller duration skew (the worker's
loop and the sampling window share `DURATION`).

- The worker runs in an exclusively owned disposable worker container
  (one per run, named by `run_id`, carrying a `soak-run-id` ownership
  label), shares the consumer-shell network namespace, and receives
  the donor shell's proxy env plus the token coordinates from
  `tests/consumers/scripts/common.sh` (single source, no duplication).
  After the join, the worker container is retired (`docker stop`,
  which freezes the worker while retaining its filesystem), its
  result is copied out (`docker cp` — never read from a live
  filesystem), and then it is removed authoritatively (`docker rm
  -f`); an unconfirmed removal fails closed to `FAIL_CLEANUP`. A
  failed retirement fails the result closed (outcomes honestly
  unavailable). A dispatched-but-unconfirmed creation is reconciled
  by its ownership label before anything is claimed. The harness never
  host-signals container processes.
- The worker is static bytes (every parameter arrives via argv, so the
  revision fingerprint is stable): a paced sign loop with per-op
  `timeout -k` bounds, outcome classification (0 success, 124 timeout,
  127 unknown, anything else error), microsecond busy-time accounting
  via `EPOCHREALTIME` (the worker is bash-only: BusyBox `date` has no
  `%N`), per-op checkpoints (`complete:false` partials at the result
  path rewritten after every finished op, atomic via tmp+rename, so a
  killed worker's finished work survives up to the in-flight write),
  and a terminal `soak-worker-result/1` record at a unique per-run
  path. Backward clock steps clamp an op's busy time to zero
  and count it (`clamped_ops`; any clamping nulls the busy rate). The
  worker exports `LC_ALL=C` (its `EPOCHREALTIME`/`awk` parsing must
  not depend on locale), and its window starts after every setup cost
  (a bounded setup stall shrinks the window, never zeroes it). The
  controller validates that record strictly (exact schema, run match,
  counts summing to offered, int64-representable bounds): any
  deviation is a foreign or corrupt record, never a version to
  tolerate.
- Each run provisions a run-unique key pair (no cleanup/delete cycle:
  deletes poison the proxy's subsequent finds in the observed stack,
  so soak keys accumulate by design on the disposable test token) and
  a trial sign proves the key usable before any load runs
  (refuse-before-work).
- The verdict is `PASS` or `FAIL_*` with explicit `reasons`; every
  started run writes a valid versioned JSON summary
  (`soak-summary/1`, atomically). Signals write a terminal
  `FAIL_INTERRUPTED` record and keep their 128+signal exit status. The
  record carries worker outcomes validated before the signal (never
  re-nulled); when the main flow has not validated yet, the handler
  first freezes the worker (`docker stop`), copies, and validates its
  latest checkpoint under the same bounds, so finished work survives
  the interrupt as an explicit partial. A published terminal record is
  never overwritten: the publication latch commits only after the
  rename succeeds.
- Verdict precedence is `FAIL_WORKLOAD` over `FAIL_RESULT` over
  `FAIL_CLEANUP` over `FAIL_RSS_GROWTH` over `FAIL_FD_GROWTH` over
  `FAIL_SAMPLER`. A worker that never acknowledges is unfinished
  (even when a valid result file exists — the ack is mandatory, though
  a valid complete record's outcomes are still published); a missing
  or invalid result voids the work evidence; unverifiable cleanup
  outranks measured growth; measured growth outranks unevaluable
  windows.
- RSS/FD growth is judged on positional baseline/final windows (first
  / last `SOAK_WINDOW_SAMPLES` post-warmup rows; each value is the
  median of the usable cells within, null when the window holds none).
  RSS growth compares exact KiB against limit*1024 (no MB truncation:
  a zero limit forbids any positive growth). Medians use the
  nearest-rank middle (compare.py's p50). Warmup rows never enter the
  windows but still anchor the raw initial/final endpoints.
  Unavailable cells stay empty (never zero); a window with no usable
  cell fails the sampler dimension, not the growth verdict. Daemon FD
  reads propagate `ls` failures explicitly (the daemon's `sh` is
  BusyBox ash without pipefail), so a failed listing is an empty cell,
  never `wc`'s zero.
- Rates are distinguished, never conflated: `completed_per_wall_s`
  and `ok_per_wall_s` are wall throughput over the worker's measured
  `elapsed_s` (the matched population interval — never the
  controller's sampling window); `completed_per_busy_s` is completed
  work per aggregated busy second. The busy rate is deliberately not
  named `per_busy_second`: compare.py's rate is success-only, while
  the worker aggregates busy time across every finished op. Any rate
  with a zero/unmeasured denominator is null, as is the busy rate when
  any op's timing clamped.
- Receipt reuse: provider/workload identities use compare.py's
  identity keys verbatim (`module`, `image`, `config_fingerprint`;
  `revision`, `corpus_hash`). This is a reduced diagnostic receipt,
  not a full benchmark manifest: it omits `source_head`,
  `dirty_patch_hash`, `profile`, `build_id`, and `target_abi` (no
  build is quoted; the manifest identifies the load, it does not
  certify a number). The config fingerprint is the daemon image id
  (the daemon config is baked into its image at build time).
  Operation outcomes use compare.py's outcome vocabulary, aggregated
  into the `_count_outcomes` shape (`censored` is always 0 and `total`
  equals offered): per-sample records would run to ~180k entries and
  add nothing to the verdict. A terminal record counts every op it
  covers; a killed worker's record is an explicit `complete:false`
  partial (per-op atomic checkpoints bound the uncovered suffix to
  the in-flight write), never a silently short total.
- Verdict limits are recorded inputs, not magic numbers: `limits`
  carries `max_rss_growth_mb`, `max_fd_growth`, and `provenance`
  (`default`, `explicit`, or `mixed`). No universal threshold is
  invented: extended runs declare their own duration/load/resource
  thresholds (Q15).
- A refused daemon image inspect nulls the identity with a recorded
  reason (the run stays valid; comparability suffers); a hung inspect
  refuses outright, as do an unmeasurable daemon PID/RSS/FD set, a
  missing shim module path, or any failed/hung setup step (exit 2,
  nothing ran, no summary).
- Exit status: 0 on `PASS`; 1 on a `FAIL_*` verdict; 2 on usage/setup
  errors; 128+signal on signals.
- The `SOAK_*` environment overrides exist so the harness itself can
  be tested deterministically; defaults are the production values.
  TEST ONLY seams (never set in production): `SOAK_UPTIME_PATH`
  redirects the monotonic clock for failure injection, and
  `SOAK_PUBLISH_HOLD` / `SOAK_REMOVAL_HOLD` hold the
  pre-publication / pre-removal points while their marker files exist
  (signal-timing tests), acknowledging the hold at `<marker>.ack` so
  tests barrier on the hold itself. See
  `tests/scripts/test_perf_harnesses.py`.

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

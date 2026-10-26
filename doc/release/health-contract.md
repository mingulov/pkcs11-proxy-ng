# Daemon health contract

This document states what daemon readiness **means** and what it
deliberately does **not** cover. It is normative for operators: monitoring
and orchestration may rely on the behaviors below; anything not listed
here is not promised.

## 1. Protocol

The daemon serves the standard gRPC Health Checking Protocol
(`grpc.health.v1`) via `tonic-health`, on the same listener as the
proxy RPCs. There is no separate unauthenticated health port.

- The per-service check name is `pkcs11_proxy_ng.v1.Pkcs11Proxy`
  (`crates/server/src/server/health.rs`, `SERVICE_NAME`).
- The daemon only ever flips the status of its own service name. The
  empty-service (`""`) check does not reflect backend health; use it
  for generic listener liveness at most.

## 2. Lifecycle states

| Phase | Status for `pkcs11_proxy_ng.v1.Pkcs11Proxy` |
| --- | --- |
| Startup, before the backend module is loaded and slots are populated | `NOT_SERVING` (internal, see below) |
| Listeners bound, ready for PKCS#11 traffic | `SERVING` |
| Backend-health gate tripped (see §3) | `NOT_SERVING` |
| Next reported backend success after a trip | `SERVING` again |

The startup `NOT_SERVING` is internal reporter state, not an
observable phase: `set_serving` runs before the serve futures are
first polled (`crates/server/src/main.rs`), so externally the daemon
transitions from unreachable straight to `SERVING` (or later to
`NOT_SERVING` if the gate trips).

`NOT_SERVING` means "do not send traffic", not "the process is
broken". A `NOT_SERVING` daemon still serves the health RPC itself so
probes keep reporting the verdict instead of timing out.

## 3. Backend-health gate

While serving, classified `spawn_backend` / `spawn_backend_exact`
wrapper outcomes are reported to a gating task
(`spawn_backend_health_gate` in `crates/server/src/main.rs`). The gate
sees wrapper outcomes, not raw native calls (§4):

- It counts **consecutive** backend failures. When the count reaches
  `proxy.backend_health_consecutive_failures` (default `3`, must be
  `> 0`; `packaging/config/proxy.toml.default`), the gate flips the
  service to `NOT_SERVING` and logs `backend exceeded failure
  threshold; flipping readiness to NOT_SERVING`.
- The **next reported backend success** resets the counter and flips
  back to `SERVING` (`backend recovered; flipping readiness back to
  SERVING`).
- Success reports are coalesced to unhealthy→healthy transitions —
  steady-state success traffic sends nothing.
- Delivery is best-effort, not lossless. The outcome channel is
  bounded (256 events) and reported with `try_send`, so a saturated
  buffer drops outcomes. Two consequences operators should know:
  the success-coalescing flag flips before the send, so a dropped
  `Success` delays recovery until the next failure-then-success
  pair; and a threshold configured far above the buffer capacity
  weakens the "a full buffer already exceeds the threshold"
  reasoning. Keep the threshold small (the default `3`); do not
  treat a trip or a recovery as atomic with the backend outcome
  that caused it.

## 4. What counts as unhealthy

Classification lives in `classify_backend_outcome`
(`crates/server/src/server/grpc_service/service_utils.rs`):

**Unhealthy** (drives the gate toward `NOT_SERVING`):

- Backend-returned `CKR_HOST_MEMORY` and `CKR_DEVICE_REMOVED` — the
  device reports it is gone or out of memory. One client's request
  shape cannot induce these, so repeats are a daemon-readiness
  signal.
- Daemon transport failures: backend-call timeout, global
  circuit-breaker trip, blocking-pool panic.

**Healthy** (resets the consecutive counter; a lone healthy call amid
failures still breaks the streak):

- Every other backend-returned `CK_RV`, including
  `CKR_DEVICE_ERROR` and `CKR_TOKEN_NOT_PRESENT`, which are
  per-request responses, not daemon-down signals. The exact backend
  RV is still returned to the caller unchanged, except on an
  exact-output contract violation, where the caller gets the
  unified `CKR_DEVICE_ERROR` while health classification keeps the
  original provider RV.

**Never reaches the gate:**

- Handler-level refusals that return before invoking
  `spawn_backend` at all (unknown session/handle, policy deny,
  input-sanitization refusal).
- Exact-family pre-native rejections (`spawn_backend_exact` with a
  `Rejected` origin), which emit neither event by construction.

Two sharp edges, stated so nobody is surprised:

- The ordinary `spawn_backend` path classifies whatever `CkResult`
  its closure returns, wherever the failure originated. A closure
  that fails locally before native entry — e.g. an oversize
  `GenerateRandom` length rejected by the backend wrapper — is
  classified like any other RV (healthy, in that example) and can
  signal recovery.
- Background teardown feeds the gate too. Lease-reaping
  `close_session` calls discard the backend RV and report healthy,
  while a teardown timeout or breaker trip reports `Failure` like
  any transport failure (those branches report before returning).

## 5. Probing

- `pkcs11-proxy-ng-cli health` exits `0` if SERVING, `1` if
  NOT_SERVING, `2` if the probe itself fails (connect error,
  TLS error, indeterminate status). `diagnostics` uses the same
  exit codes and adds the context-free interface report; neither
  initializes a PKCS#11 context, so both are safe under
  `max_contexts = 1`.
- The Kubernetes example (`examples/k8s/20-daemon-deployment.yaml`)
  wires readiness to `exec: [pkcs11-proxy-ng-cli, --endpoint, ...,
  health]` so a backend hang pulls the pod out of the Service
  endpoints. Liveness is deliberately a laxer TCP check: `NOT_SERVING`
  must shed traffic, not restart the process. A remote mTLS listener
  needs the full TLS flags on the probe (see the install guide §5);
  a plaintext probe against an mTLS listener fails by design.

## 6. Shutdown behavior

On SIGTERM/SIGINT the daemon stops accepting new connections and
drains under `proxy.shutdown_grace_secs`. Shutdown performs **no**
health-status flip: probes observe transport errors or stall past
their timeout (the CLI probe has a 2s connect timeout; the k8s probe
has its own `timeoutSeconds`) instead of a `NOT_SERVING` verdict,
and in-flight health RPCs may still complete with the previous
status. Either way the pod leaves rotation. Do not alert on a brief
failed-probe window during a rollout restart — alert on persistent
`NOT_SERVING` with a healthy listener instead (triage: runbook §6).

## 7. Metrics inventory (what exists today)

- A Prometheus endpoint (`GET /metrics`, text exposition v0.0.4)
  on an opt-in Unix-domain socket (`resilience.metrics_socket`):
  ten counters and one gauge, no latencies, no histograms.
  Counters: `pkcs11_proxy_find_objects_total`,
  `pkcs11_proxy_find_objects_over_threshold_total`,
  `pkcs11_proxy_get_attribute_value_total`,
  `pkcs11_proxy_audit_emitted_total`,
  `pkcs11_proxy_audit_dropped_total`,
  `pkcs11_proxy_rate_limit_rejected_total`,
  `pkcs11_proxy_session_quota_rejected_total`,
  `pkcs11_proxy_login_budget_tripped_total`,
  `pkcs11_proxy_attr_coalesce_hits_total`,
  `pkcs11_proxy_attr_coalesce_misses_total`.
  Gauge: `pkcs11_proxy_find_result_size_max` (largest single
  `C_FindObjects` result observed).
- Every audit record carries a per-call `latency_us` field. That is
  raw per-record material for offline analysis, not an aggregated
  metric and not an SLO input. System records
  (`__attestation__`, `__AUDIT_GAP__`) carry `latency_us = 0` —
  offline aggregation must filter to operation records.

## 8. Explicit non-goals

The following are **explicit non-goals** of this release line, not
roadmap items hiding by omission:

1. **No per-RPC latency metrics or histograms.** Per-call latency in
   this system is HSM-dominated: backend time swamps proxy overhead,
   so proxy-side percentiles would mostly re-measure the attached
   token, not the proxy. Operators who need latency distributions
   today should aggregate the audit log's `latency_us` field
   offline.
2. **No named SLOs and no error budgets.** v0.2 supports one logical
   client in one trusted domain per daemon instance (a testing
   scope, not a multi-tenant service), so service-level numbers
   would be unenforceable promises. The one existing "SLO" mention
   (the rolling-restart comment in `20-daemon-deployment.yaml`) is
   rollout policy, not a latency/availability target, and must not
   be read as one.

Re-entry condition: latency metrics and/or named SLOs may return only
with their own design note, real-backend evidence across more than one
provider, and an update to this section that retires the non-goal in
the same change. Until then, no dashboard, alert, or contract may
cite a proxy latency percentile or availability target as promised.

## Pointers

- Triage for `NOT_SERVING`: [runbook
  §6](../runbooks/operating-pkcs11-proxy-ng.md#6-troubleshooting-common-ck_rv-codes).
- Outcome classification and per-RV operator actions: [error
  reference](../error-reference.md).
- mTLS probe recipe: [bundle install §5](bundle-install.md).
- Chaos coverage of the gate transition:
  `tests/chaos/scenarios/scenario2_backend_oom.sh`.

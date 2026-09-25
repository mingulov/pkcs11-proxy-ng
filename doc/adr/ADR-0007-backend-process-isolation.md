# ADR-0007: Backend Process Isolation

## Status
**Deferred / not adopted (2026-05-30).** Superseded by an operational approach — see the
decision update directly below. The proposal text is retained unchanged as a documented
fallback.

## Decision update (2026-05-30): deferred in favor of multi-daemon isolation

A deep review re-evaluated the in-process worker proposed here and **deferred** it:

- An in-process worker does **not** make a backend crash transparent — PKCS#11
  session/login/multipart/operation state is un-serializable and dies with the backend
  regardless; the client must re-establish it either way, so the client-visible failures the
  worker was meant to prevent still occur.
- The worker's only unique benefits — keeping the shared daemon's connections alive through a
  crash, and killing a *hung* backend (in-process, a timed-out FFI call orphans its thread) —
  are low-value for a deployment that accepts full restarts and client reconnection.

**Chosen strategy instead (zero new code):** run **multiple `pkcs11-proxy-ng` instances**,
partition clients across them with **sticky** routing (a session handle is valid only on the
daemon that created it — never round-robin individual calls across instances), and let the
orchestrator (systemd / k8s / docker) restart a failed instance. OS address-space isolation
per instance contains a backend crash to that instance's clients — what the original Decision
sought — and the remaining client-visible failures are handled by **client reconnect/re-open**,
not a daemon-side change.

The proposal below, plus the design spec
`doc/plans/2026-05-30-backend-process-isolation-design.md`, is kept as a documented fallback
for a future single-endpoint, many-client deployment that needs crash-survivable connections
or hung-backend termination.

## Context

The backend PKCS#11 module is loaded **in-process** in the daemon: the gRPC
server and the vendor `.so` share one address space (ADR-0004 defines the
`Pkcs11Backend` trait as the abstraction boundary, with `FfiBackend` the
in-process implementation). Therefore **any** client request that crashes the
backend — a SIGSEGV inside the vendor library — crashes the **entire daemon**,
severing **every** client's connection and losing all in-flight operations, not
just the offending client's.

This was observed directly in the 2026-05-30 transparency sweep: NSS softoken
SIGSEGVs on several `security/test_api_boundary.py` malformed-argument cases.
Through the proxy a single such crash took the shared daemon down for the rest of
the run (≈21k spurious `CKR_DEVICE_ERROR` until the supervisor restarted it). The
harness/operations layer can restart the daemon (systemd `Restart=always`, k8s,
the test supervisor), but restart does not remove the collateral damage:

- all OTHER clients' connections drop and their in-flight ops fail at the moment
  of crash;
- every client's logical context/session state is lost (the backend re-inits
  fresh); and
- a client that can reliably crash the backend has a cheap, repeatable
  cross-tenant denial-of-service.

This contradicts the proxy's core value proposition: a memory-safe Rust layer
shielding callers from a flaky/native module.

## Decision

Run the backend `.so` in a **separate worker process**, behind the existing
`Pkcs11Backend` trait, so a backend crash kills only the worker — the gRPC
server stays up, fails just the routed call, respawns the worker, and other
clients are unaffected.

The codebase is well-positioned: `Pkcs11Backend` (≈104 methods) is already the
abstraction the daemon holds as `Arc<dyn Pkcs11Backend>`, with two
implementations shipping (`FfiBackend`, `MockBackend`). Isolation adds a third —
`IpcBackend`, which marshals trait calls to a thin worker binary that hosts the
existing `FfiBackend` (no context manager). Everything above the trait — context
manager, virtual-handle mapping, leases, auth, the exact/raw two-call
orchestration — is unchanged. Two PKCS#11 facts remove the usual blockers:
`C_Initialize` is called with `CKF_OS_LOCKING_OK` and NULL mutex callbacks (no
callbacks to marshal across the boundary), and no `CK_NOTIFY` is wired.

**Staged, behind the in-process default (opt-in):**

1. Define the worker protocol at **trait granularity**, reusing the existing
   proto/client/server stack for the daemon↔worker hop.
2. `IpcBackend` + worker binary; **single worker**, opt-in via config.
3. On worker death: invalidate the affected contexts/sessions, keep the gRPC
   server up, return clean per-client `CKR_*`, respawn + re-`C_Initialize`,
   bounded by the existing backend circuit breaker.
4. Fault-injection test (a `MockBackend` that SIGSEGVs on a flagged op): assert
   the server survives, the offending call fails cleanly, the worker respawns, a
   concurrent second client is unaffected.
5. Later: worker pool / per-token isolation, and a reduced-privilege worker
   (seccomp / separate uid / namespaces) to contain a *compromised* module.

Detailed feasibility, gap table, and the marshalling-fidelity risk are in
`pkcs11-proxy-ng/doc/follow-up-backend-crash-isolation.md`.

## Consequences

**Positive.** A backend crash no longer downs all clients; the gRPC server and
unaffected clients survive. Worker respawn is a fresh process, which also avoids
the "NSS softoken can't cleanly re-`C_Initialize` in the same process" problem.
Enables privilege separation (defence in depth for a compromised module).

**Negative / costs.** One extra local IPC hop per backend call (uds/shared-mem,
~tens of µs vs the gRPC + crypto cost — usually negligible; mitigated by
shared-memory ring / batching / opt-in for hot paths). Volatile state (open
sessions, login, in-progress ops, session objects/keys) is still genuinely lost
on a crash — token (persistent) objects survive; clients re-open/re-login. The
biggest correctness risk is exact-output marshalling fidelity (the proxy's core
property) across the new hop — covered by running the existing real-backend
integration suite against the worker path.

**Interim posture (until implemented).** Operations hardening — `Restart=always`
/ k8s liveness, fast restart, a crash-rate alert — plus the harness supervisor's
auto-restart (the project's proxy-test harness supervisor). The
cross-client blast radius is a known, documented limitation.

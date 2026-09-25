# Follow-up: isolate the backend so its crash doesn't take down all clients

> **STATUS (2026-05-30): DEFERRED — superseded by operational multi-daemon isolation.**
> After a deep review, the in-process-worker approach below was **not adopted**. It does not
> make a backend crash transparent (PKCS#11 session/login/op state is un-serializable; the
> client must re-establish it regardless), and its unique wins are low-value for a project
> that accepts full restarts + client reconnection. The chosen strategy is to **run multiple
> daemon instances + sticky client routing + client reconnect**, supervised by the
> orchestrator. This document and ADR-0007
> (`doc/adr/ADR-0007-backend-process-isolation.md`) are kept as a
> documented fallback. See the A2 entry in `follow-up-index.md`.

## The gap

The backend PKCS#11 module is loaded **in-process** in the daemon (the gRPC
server and the backend `.so` share one address space). Therefore **any** client
request that crashes the backend (a SIGSEGV inside the vendor `.so`) crashes the
**entire daemon**, severing **every** client's connection and losing all
in-flight operations — not just the offending client's.

This is a real availability / cross-client DoS surface: one buggy or hostile
client can take down the proxy for everyone, repeatedly.

## How it surfaced (2026-05-30)

pkcs11-check's `security/test_api_boundary.py` deliberately feeds malformed
arguments (NULL templates, bad pointers) to find modules that crash instead of
returning a clean `CK_RV`. Against **NSS softoken** several of these make the
module **SIGSEGV (exit 139)**. Direct, pkcs11-check observes the crash per-file
(process isolation) — that IS the finding. Through the proxy, the SIGSEGV killed
the shared daemon; without a working restart, every subsequent `C_Initialize`
failed with `CKR_DEVICE_ERROR` (≈21k cascade in one sweep).

The transparency harness now restarts the daemon on crash (see
`docker/proxy-test/pool/proxy-inject.sh`), which contains the blast radius to the
single crashing op + a sub-second restart window. Production deployments rely on
the same external restart (systemd `Restart=always`, k8s liveness/restart). This
follow-up is about doing better than "restart the whole thing".

## Why "just restart" is not enough

Even with instant restart:
- All OTHER clients' connections drop and their in-flight ops fail at the moment
  of crash — collateral damage from one client's input.
- Logical context/session state for every client is lost (the backend
  re-initializes fresh), so well-behaved clients must re-establish everything.
- A client that can reliably crash the backend has a cheap repeatable DoS.

## Options (in increasing order of effort/robustness)

1. **Document + harden ops** (cheap): require `Restart=always` and a fast restart;
   ensure a clean `CKR_DEVICE_ERROR`/reconnect path on the client (already the
   case). Add a crash-rate circuit breaker / alert. Does not remove the collateral
   damage.

2. **Backend in a worker subprocess** (medium/large): run the vendor `.so` in a
   separate process (or a small pool) that the daemon talks to over a local IPC
   (pipe/uds/shared-mem). A backend SIGSEGV then kills only the worker; the gRPC
   server stays up, fails just the in-flight calls routed to that worker, respawns
   it, and other clients are unaffected. This is the standard "sandbox the native
   plugin" pattern. Cost: an extra IPC hop + marshalling, and worker lifecycle
   management. Biggest robustness win.

3. **Per-tenant / per-token worker isolation** (large): pin a worker per token or
   per trust domain so a crash can't even cross tenants. Strongest isolation,
   highest cost; likely overkill unless multi-tenant hostile.

## Recommendation

Option 2 is the principled fix and aligns with the proxy's value proposition
(memory-safe Rust shielding callers from a flaky native module). It is a
significant architectural change — propose an ADR and stage it behind the current
in-process path. Until then: Option 1 (ops hardening) + the harness/prod
auto-restart is the interim posture, and the cross-client blast radius is a known,
documented limitation.

## Tests

- A fault-injecting backend (there is already `docker/fault-proxy.c` /
  `MockBackend` machinery) that SIGSEGVs on a flagged op: assert the gRPC server
  stays up, the offending call fails cleanly, the worker respawns, and a
  concurrent second client is unaffected.

## Feasibility & gap analysis (2026-05-30 codebase review)

**Verdict: feasible, and the codebase is unusually well-positioned for it.** Option
2 (backend in a worker subprocess) is the recommended target.

### Why it's tractable — the seam already exists

- `Pkcs11Backend` (crates/backend/src/traits.rs, ~104 methods) is THE abstraction
  boundary, and the daemon holds `Arc<dyn Pkcs11Backend>` everywhere (`backend_ref`
  threaded through every handler). **Two impls already ship** (`FfiBackend`,
  `MockBackend`), so the polymorphism is load-bearing and proven. Isolation =
  add a third impl `IpcBackend` (marshals trait calls to a worker) + a thin worker
  binary that hosts the existing `FfiBackend`. Everything above the trait — context
  manager, virtual-handle mapping, leases, auth, mechanism registry, the exact/raw
  two-call orchestration — is **unchanged**.

### PKCS#11-specific facts that remove the usual blockers

- C_Initialize is called with `CKF_OS_LOCKING_OK` and `CreateMutex: None`
  (crates/backend/src/ffi.rs) — **no custom mutex callbacks** to marshal across the
  process boundary; the module self-locks, so the worker may be multi-threaded.
- **No `CK_NOTIFY`** session callbacks are wired — no async callback channel from
  worker → daemon → app to build.
- The shim already does exact/raw **two-call** buffer semantics ABOVE the trait, so
  the worker only ever makes single FFI calls — no buffer-size renegotiation across
  the new hop.
- A worker respawn is a **fresh process**, which sidesteps the "NSS softoken can't
  cleanly re-`C_Initialize` in the same process" problem the in-process path has.

### Reuse (library-first, no NIH)

The proxy already has a client/server/proto/serialisation stack (shim↔daemon). The
daemon↔worker hop can reuse it: the worker is a minimal server wrapping `FfiBackend`
with NO context manager (raw backend only), and `IpcBackend` is essentially the
existing client pointed at the worker's local socket. Define messages at the
**trait granularity** (raw backend calls), reusing existing proto types.

### The real gaps / hard parts

| Gap | Size | Notes |
|---|---|---|
| Marshal the 104-method trait over IPC | M (large but mechanical) | Risk concentrates in the exact-output methods (`sign_exact`, `encrypt_exact`, `get_attribute_value_exact`, `encapsulate_key_exact`) — already typed; serialize in/out types. |
| Handle lifetime = worker lifetime | M | Real session/object handles are valid only in the worker; on crash ALL die. Daemon must detect worker death, invalidate the affected contexts/sessions, KEEP the gRPC server + connections up, return clean per-client `CKR_DEVICE_ERROR`/`SESSION_HANDLE_INVALID`, respawn + re-init. **This is the win:** blast radius shrinks from "all connections dropped + full daemon restart" to "sessions on the dead worker invalidated; server keeps serving new C_Initialize." |
| Volatile state lost on crash | inherent | Open sessions, login, in-progress ops, session objects/keys are gone (lived in the crashed module). Token (persistent) objects survive. Clients re-open/re-login. Acceptable: a clean per-client failure beats a total outage. |
| Worker model | design choice | Start with ONE worker (daemon survives any backend crash). Worker-pool / per-token isolation = finer blast radius, later. |
| Performance | S–M | +1 LOCAL IPC hop per backend call (uds/shm, ~tens of µs) vs the gRPC network hop + crypto → usually negligible; matters only for high-throughput tiny ops. Mitigate with shared-memory ring / batching / opt-in. |
| Worker lifecycle | M, pattern known | Daemon spawns/monitors/respawns the worker with a bounded restart policy + the EXISTING backend circuit breaker (so a crash-looping op trips the breaker, not infinite respawn). Same crash-restart shape as the harness supervisor. |
| Config + ADR | S | Opt-in flag behind the in-process default; new ADR (sibling to ADR-0004 backend-integration-model). |

### Bonus: privilege separation

A worker process can also run under a reduced-privilege profile (separate uid /
seccomp / namespaces), containing a *compromised* (not merely crashing) module —
strengthening the proxy's "memory-safe Rust shields callers from a flaky native
module" value proposition. The in-process design cannot do this.

### No showstoppers found

NSS `pReserved` config is passed at worker init; modules that cache fds/shm across
init get a clean fresh process on respawn; the trait is sync and the daemon already
wraps backend calls in `spawn_blocking`, so a blocking local IPC round-trip fits
without reworking the async model.

### Recommended staging

1. ADR for the decision (sibling to ADR-0004).
2. Define the worker protocol at trait granularity (reuse proto/client/server).
3. `IpcBackend` + worker binary as a **single-worker, opt-in** path behind the
   in-process default.
4. Wire worker-death → context/session invalidation + circuit breaker; gRPC server
   stays up.
5. Fault-injection test (MockBackend SIGSEGVs on a flagged op): server survives,
   offending call fails cleanly, worker respawns, concurrent second client
   unaffected.
6. Later: worker pool / per-token isolation + privilege separation.

Biggest single risk is **exact-output marshalling fidelity** (the proxy's core
correctness property) — cover it by running the existing real-backend integration
suite against the worker path.

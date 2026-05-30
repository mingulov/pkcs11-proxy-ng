# Follow-up: isolate the backend so its crash doesn't take down all clients

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

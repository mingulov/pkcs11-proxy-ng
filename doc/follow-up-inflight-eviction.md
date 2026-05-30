# Follow-up: make context eviction in-flight aware

## The bug

`ContextManager` evicts a logical client context once
`now - last_active > lease_duration` (`crates/server/src/server/context_manager.rs`,
`collect_expired_context_ids` / the inline filter in `create_context`). `last_active`
is refreshed by `touch()`, which runs when an RPC **resolves** the context — i.e. at
the *start* of an operation, not during it.

A single backend operation that runs longer than `lease_seconds` therefore lets its
context go stale and the periodic evictor (every `eviction_interval_secs`) removes it
**mid-call**, closing its backend sessions underneath the in-flight operation. The
operation then fails / the next call observes `CKR_SESSION_HANDLE_INVALID`, and a
follow-on call sees `CKR_CRYPTOKI_NOT_INITIALIZED`.

## Reproduction (observed 2026-05-30)

`pkcs11-check test_dh_key_agreement.py::TestDHParameterGeneration::test_generate_dh_parameters`
through the proxy on SoftHSM2: DH parameter generation is a single ~37s
`C_GenerateKey`. With the default `lease_seconds = 30` the context is evicted at 30s
and the call fails ~37s in with `CKR_SESSION_HANDLE_INVALID` (direct passes). Any slow
single op reproduces it: large RSA/DH keygen, safe-prime generation, slow-HSM ops.

This is a real-deployment correctness bug, not just a test artifact — real HSMs
routinely take >30s for RSA-4096 / DH-param generation.

## Why it matters

The proxy must be transparent for slow operations. Today an operation slower than the
lease is silently broken. Operators can work around it by raising `lease_seconds`, but
that (a) is fragile (must exceed the slowest op) and (b) makes orphaned contexts from
crashed clients linger longer.

## Recommended fix: in-flight-aware eviction

Track in-flight backend operations per context and refuse to evict a busy context.

1. Add `in_flight: Arc<std::sync::atomic::AtomicI64>` to `LogicalClientInstance`
   (Arc so it can be cloned out from under the `DashMap` shard guard and held across
   the backend call without holding the lock).
2. A RAII `OperationGuard` increments on creation and decrements on `Drop`. Obtain it
   where the RPC resolves the context/session (the same place that calls `touch()`),
   so its scope spans the subsequent `spawn_backend(...)` call. Decrement should also
   `touch()` the context so a just-completed long op isn't immediately evicted.
3. Eviction filters add `&& entry.in_flight.load(Relaxed) == 0` to BOTH eviction
   sites (`create_context`'s opportunistic eviction and `collect_expired_context_ids`).
4. Optional safety valve: cap how long a context may stay un-evictable via in-flight
   (e.g. a hard ceiling = `request_timeout_secs`) so a wedged backend call can't pin a
   context forever — the circuit breaker / request timeout already bounds call length.

`spawn_backend` is the backend choke point but has many call sites; prefer attaching
the guard at session-resolution time (one or few helpers) rather than wrapping every
`spawn_backend`.

### Alternative (simpler, less precise)

Heartbeat: while a backend call for a context is running, a lightweight task `touch()`es
the context every `lease/3`. Keeps `last_active` fresh during long calls. Avoids a new
field but needs the async heartbeat plumbed into the backend-call path.

## Tests

- Unit: a mock backend whose op blocks for `2 * lease`; assert the context is NOT
  evicted while the op is in flight and the op returns normally; assert an idle
  (orphaned) context IS still evicted after the lease.
- Regression: with `lease_seconds` small, a slow `C_GenerateKey` round-trips OK.

## Risk

Concurrency-sensitive core change (shared context model, DashMap, eviction task). Needs
race-free inc/dec and careful ordering with `remove_context`/`teardown`. Implement with
the unit tests above and run the existing `stress_registry` / context-manager tests.

## Interim mitigation

The proxy-transparency harness sets `lease_seconds = 600` and `request_timeout_secs = 120`
in `docker/proxy-test/pool/proxy-config.toml` so slow test ops complete. Not a fix.

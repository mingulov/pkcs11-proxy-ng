# Follow-up index — open items from the 2026-05-30 transparency sweep

Prioritized by impact. The mechanism-transparency regressions found in the sweep
were FIXED (ML-DSA/SLH-DSA hash-variant context params; SSL3/TLS key-and-mac NULL
phKey). These are the remaining items.

## Tier A — real correctness / robustness (production-relevant)

- **A1. In-flight-aware context eviction** — ✅ **FIXED (2026-05-30)**.
  `follow-up-inflight-eviction.md`. Per-context `in_flight` counter +
  `OperationGuard` taken once in the gRPC dispatch macro; eviction skips busy
  contexts. Verified: DH param-gen 2 failed → 6 passed at the default lease=30
  (plus a unit test). No per-handler churn.

- **A2. Backend process isolation + reduced-privilege worker** —
  `follow-up-backend-crash-isolation.md` (incl. full feasibility/gap analysis).
  Backend runs in-process, so any client's crash-input downs the shared daemon for
  ALL clients. Move the backend into a worker subprocess (the `Pkcs11Backend` trait
  is the ready-made seam) so a crash kills only the worker; bonus privilege
  separation (seccomp/uid). ADR + staged rollout. Big robustness + security win.

## Tier B — mechanism-transparency completeness

- **B1. Generic `CKM_HASH_ML_DSA` / `CKM_HASH_SLH_DSA`** — need the
  `CK_HASH_SIGN_ADDITIONAL_CONTEXT` shape (adds a `hash` CK_MECHANISM_TYPE field vs
  the plain `CK_SIGN_ADDITIONAL_CONTEXT` already supported). Closes the 4 residual
  kryoptic behaviour-Δ (`CKR_FUNCTION_NOT_SUPPORTED` direct → `CKR_MECHANISM_PARAM_INVALID`
  proxied). New param shape through all layers (proto/types/ffi/registry + tests).

- **B2. Message-based API remoting** — `C_MessageEncryptInit` etc. with
  `CK_GCM_MESSAGE_PARAMS` are not remoted (known gap on kryoptic AND nss message
  tests). Medium.

## Tier C — minor / optional

- **C1. Unix-domain-socket transport for the shim/client** (optional). Today the
  client only dials `http://` (no unix connector) and the server binds TCP
  (`UnixListenerConfig` exists but is unwired) — so it needs BOTH ends. Value:
  on-host perf + `SO_PEERCRED` peer-auth; NOT a robustness fix (it would not have
  prevented the nss cascade, which was a supervisor crash-recovery bug). Low
  urgency.

- **C2. Legacy PBE `pInitVector` writeback** — `C_GenerateKey` + `CK_PBE_PARAMS`
  doesn't propagate the generated init vector (4 nss tests). Deprecated mechanism;
  multi-layer like the SSL3/TLS key-mat writeback. Low.

- **C3. softhsm2 wrap-key error code** — undersized AES wrap key →
  `CKR_GENERAL_ERROR` (proxied) vs `CKR_WRAPPING_KEY_SIZE_RANGE` (direct). Both
  reject (negative path). Confirm whether the proxied `C_CreateObject` of the
  undersized key is byte-identical to direct (the one unverified bit). Low.

## Separate repo — pkcs11-check
See `docker/proxy-test/pool/pkcs11-check-backlog.md` (root repo): structured
per-call CK_RV trace, 10000× C_Initialize churn/exhaustion test, mid-file
daemon-restart handling.

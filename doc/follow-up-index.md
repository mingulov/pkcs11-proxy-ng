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

- **B1. Generic `CKM_HASH_ML_DSA` / `CKM_HASH_SLH_DSA`** — ✅ **FIXED (2026-05-30)**.
  Extended `SignAdditionalContext` with an optional `hash` field (size-aware shim
  read + dual C-struct reconstruction CK_SIGN_/CK_HASH_SIGN_ADDITIONAL_CONTEXT,
  mirroring the SSL3-vs-TLS12 key-mat precedent — DRY, no new shape) and mapped
  0x1F/0x34 to the shape. Verified: kryoptic hash-ML-DSA & hash-SLH-DSA proxied ==
  direct exactly (25/9/8); pure ML-DSA unchanged (263/72/80). Round-trip + FFI
  unit tests added.

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

## Tier-2 provider findings (2026-05-30 — opencryptoki/tpm2/bouncyhsm)

opencryptoki-master and tpm2: **0 regressions, PASS** (the supervisor crash-recovery
fix auto-recovers pkcsslotd/swtpm crashes). bouncyhsm: 832 regressions, dominated by:

- **D1. bouncyhsm AEAD/multipart `CKR_OPERATION_ACTIVE`** (722) — proxied returns
  `CKR_OPERATION_ACTIVE` where direct returns `CKR_OK`, on CCM/GCM decrypt + multipart.
  `C_SessionCancel` IS remoted, so this is an operation-STATE interaction (the
  exact/two-call AEAD path likely leaves an op active vs direct, or the pkcs11-check
  `CKR_OPERATION_ACTIVE` recovery doesn't clear it through the proxy). Bouncyhsm-
  specific so far (kryoptic/softhsm2/nss clean). Needs a deep operation-state review.
  Medium–high; the single biggest remaining regression cluster.
- **D2. Multipart MAC param** (~87 `CKR_MECHANISM_PARAM_INVALID`, e.g. `AES_GMAC`
  multipart) — a mechanism-param/multipart gap. Medium.
- MCT multiblock timeouts (~12) — known proxy-latency, already a known-diff class.

## Separate repo — pkcs11-check
See `docker/proxy-test/pool/pkcs11-check-backlog.md` (root repo): structured
per-call CK_RV trace, 10000× C_Initialize churn/exhaustion test, mid-file
daemon-restart handling.

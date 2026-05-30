# Follow-up index — open items from the 2026-05-30 transparency sweep

Prioritized by impact. The mechanism-transparency regressions found in the sweep
were FIXED (ML-DSA/SLH-DSA hash-variant context params; SSL3/TLS key-and-mac NULL
phKey).

**Status (2026-05-30 follow-up session):**
- ✅ **Fixed & verified vs real backend:** A1 (in-flight-aware eviction), B1
  (generic Hash-ML-DSA/SLH-DSA), **D1 (bouncyhsm 3.0-interface fallback —
  `C_SessionCancel` reachability)**. Plus the earlier ML-DSA + TLS key-and-mac
  fixes.
- 📐 **ADR + staged plan:** A2 (backend process isolation — ADR-0007). Multi-day;
  not rushed into the correctness-critical path.
- 🔍 **Root-caused + planned (multi-layer, deferred):** B2 (message-init GCM param),
  C2 (PBE writeback), D2 (GMAC multipart).
- 📎 **Known-diff / optional:** C3 (wrap-key negative-path), C1 (unix socket — the
  user marked this review-later/optional).

The fixes that were tractable and low-risk were landed (now including D1, whose
deep root-cause turned out to be a one-spot interface-loading bug, not an
operation-state rework); the substantial mechanism changes (B2/C2/D2) and the
architectural one (A2) are root-caused with a concrete plan rather than rushed —
each is its own focused, reviewable change to the proxy's correctness-critical
paths.

## Tier A — real correctness / robustness (production-relevant)

- **A1. In-flight-aware context eviction** — ✅ **FIXED (2026-05-30)**.
  `follow-up-inflight-eviction.md`. Per-context `in_flight` counter +
  `OperationGuard` taken once in the gRPC dispatch macro; eviction skips busy
  contexts. Verified: DH param-gen 2 failed → 6 passed at the default lease=30
  (plus a unit test). No per-handler churn.

- **A2. Backend process isolation + reduced-privilege worker** — 📐 **ADR written
  (ADR-0007, root `doc/adr/`)**; implementation staged. `follow-up-backend-crash-
  isolation.md` has the full feasibility/gap analysis. Backend runs in-process, so
  any client's crash-input downs the shared daemon for ALL clients. Add an
  `IpcBackend` (the `Pkcs11Backend` trait is the ready-made seam) forwarding to a
  worker subprocess hosting `FfiBackend`; a crash kills only the worker. Single-
  worker opt-in first, then worker pool / per-token + reduced-privilege (seccomp/
  uid). Multi-day change — deliberately staged behind an ADR, not rushed.

- **A3. Multi-client concurrency validation round** — 📌 **DEFERRED (TODO, revisit
  after B2/C2/A2)**. The proxy is a many-clients-to-one-shared-backend service, but
  the Docker sweep runs **one daemon per container** (isolation only) so it never
  exercises that path against a REAL backend. Grounded state (2026-05-30 review):
  multi-client support is architecturally solid and unit-tested — per-client UUID
  `ClientContextId` with isolated virtual→backend handle/session maps, login state,
  and in-flight counter (no cross-client handle collisions); backend calls run
  **concurrently** (tokio blocking pool, module loaded `CKF_OS_LOCKING_OK`, no global
  backend mutex). Existing tests: `crates/server/tests/stress_test.rs`
  (8-client sign, 6-client encrypt/decrypt on MockBackend) +
  `concurrency_and_recovery_test.rs` (cross-client handle isolation; `#[ignore]`'d
  8-client SoftHSM2). **Real gaps:** (1) no end-to-end multi-client run through the
  harness against a real backend (N shims → 1 daemon → 1 backend), and (2) no
  fairness/exhaustion tests for the GLOBAL knobs — the 200-call circuit breaker
  (`IN_FLIGHT`) and 1000-context cap are process-global, so one aggressive client
  can starve others. **Leading approach (to discuss later):** hybrid — replay the
  transparency corpus under a shared daemon via `pytest-xdist -n N` (each worker =
  a separate client process; diff each worker vs the direct baseline to catch
  cross-client state corruption across all mechanisms) PLUS a small adversarial
  flood-vs-victim probe for breaker/context-cap fairness. Not started — mechanisms
  first.

## Tier B — mechanism-transparency completeness

- **B1. Generic `CKM_HASH_ML_DSA` / `CKM_HASH_SLH_DSA`** — ✅ **FIXED (2026-05-30)**.
  Extended `SignAdditionalContext` with an optional `hash` field (size-aware shim
  read + dual C-struct reconstruction CK_SIGN_/CK_HASH_SIGN_ADDITIONAL_CONTEXT,
  mirroring the SSL3-vs-TLS12 key-mat precedent — DRY, no new shape) and mapped
  0x1F/0x34 to the shape. Verified: kryoptic hash-ML-DSA & hash-SLH-DSA proxied ==
  direct exactly (25/9/8); pure ML-DSA unchanged (263/72/80). Round-trip + FFI
  unit tests added.

- **B2. Message-based API INIT param** — 🔍 **fully root-caused + implementation
  plan (2026-05-30); deferred (6-file change)**. The message API itself IS remoted
  (`message_ops.rs` has GCM/CCM message params + IV writeback). The gap:
  `C_MessageEncryptInit(CKM_AES_GCM)` is passed a `CK_GCM_MESSAGE_PARAMS` in its
  *mechanism* (via `mech_gcm_message`), but the shim reads the mechanism with the
  CLASSIC `gcm` shape (`CK_GCM_PARAMS`) → ships the wrong struct → backend
  `CKR_MECHANISM_PARAM_INVALID`.
  **Plan (option B — DRY, reuses the existing message machinery):** `MessageParameter`
  lives in the *proto* crate while `CkMechanismParams` is in *types* (which can't
  depend on proto), so do NOT bend the mechanism path. Instead:
  1. proto: add `optional MessageParameter init_message_parameter` to
     `MessageEncryptInitRequest` + `MessageDecryptInitRequest`.
  2. shim `c_message_encrypt_init`/`decrypt_init`: send the mechanism TYPE only and
     read the init param via the existing `try_read_message_parameter`.
  3. client/server: thread the new field.
  4. `Pkcs11Backend::message_encrypt_init`/`decrypt_init`: add
     `init_param: Option<&MessageParameter>` (ripples to `FfiBackend` + `MockBackend`);
     when present, build `CK_GCM/CCM_MESSAGE_PARAMS` (reuse the `message_ops` builder,
     mind `pIv`/`pTag` buffer lifetimes) and attach it for `C_MessageEncryptInit`.
  5. verify on kryoptic (`test_mech_message.py`) + existing message tests.
  Deferred from this session: a 6-file change with FFI pointer-lifetime handling +
  a trait-signature ripple through the message-crypto path — a focused, reviewable
  change, not a session-end sprint. Related: D2 (GMAC multipart) shares this surface.

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
fix auto-recovers pkcsslotd/swtpm crashes). bouncyhsm: 832 regressions pre-fix,
of which **513 (the largest cluster, D1) are now eliminated** by the
3.0-interface fallback below; the rest are: ~87 GMAC multipart param (D2) and
~12 MCT multiblock timeouts (known proxy-latency class).

- **D1. bouncyhsm AEAD `CKR_OPERATION_ACTIVE` cascade** — ✅ **FIXED (2026-05-30)**.
  Root cause (proven, not a pkcs11-check limitation): the daemon populated
  `func_list_3_0` **only** from an explicit `C_GetInterface("PKCS 11", {3,0})`
  query. BouncyHSM answers that with `CKR_OK` **and a NULL interface** (its
  interfaces are a 3.1 default + a 3.2, no literal "3.0"), so `func_list_3_0`
  stayed `None` and `ffi_session_cancel` (dispatched solely via `func_list_3_0`,
  no fallback) returned `CKR_FUNCTION_NOT_SUPPORTED` — even though
  `C_SessionCancel` is a live pointer in both the 3.1 and 3.2 lists. BouncyHSM
  leaves the AEAD decrypt op active after `CKR_ENCRYPTED_DATA_INVALID`;
  pkcs11-check's post-failure `_cancel_operation` (`C_SessionCancel`) cleans it
  up direct but the proxy's `FUNCTION_NOT_SUPPORTED` broke that, cascading
  `OPERATION_ACTIVE` across subsequent CCM tests (513 regressions, all
  `OPERATION_ACTIVE`; 0 were param-marshalling — the GENERAL_ERROR/
  ENCRYPTED_DATA_INVALID cases fail direct too = bouncyhsm's own CCM gaps).
  **Fix:** `crates/backend/src/ffi/loading.rs` — when the explicit versioned
  query yields nothing, fall back to the primary interface for `func_list_3_0`
  when it is itself ≥ 3.0 (the 3.0 list is a prefix of every higher 3.x list);
  symmetric, version-gated fallback for `func_list_3_2`. Zero effect on modules
  that answer the explicit query (kryoptic/softhsm2/nss/opencryptoki). Verified:
  real-module loader test (fails without the fallback, passes with); end-to-end
  on bouncyhsm — `TestSessionCancel` 3/3 pass (were skip/`FUNCTION_NOT_SUPPORTED`),
  CCM decrypt slice `OPERATION_ACTIVE` 9→0 (== direct's 0). The 3.0 stubs
  BouncyHSM does *not* implement (message API, `C_LoginUser`) still return
  `FUNCTION_NOT_SUPPORTED`, matching direct — no new divergence.
- **D2. Multipart MAC param** (~87 `CKR_MECHANISM_PARAM_INVALID`, e.g. `AES_GMAC`
  multipart) — a mechanism-param/multipart gap. Medium.
- MCT multiblock timeouts (~12) — known proxy-latency, already a known-diff class.

## Separate repo — pkcs11-check
See `docker/proxy-test/pool/pkcs11-check-backlog.md` (root repo): structured
per-call CK_RV trace, 10000× C_Initialize churn/exhaustion test, mid-file
daemon-restart handling.

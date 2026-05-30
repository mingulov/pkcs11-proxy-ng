# Follow-up index — open items from the 2026-05-30 transparency sweep

Prioritized by impact. The mechanism-transparency regressions found in the sweep
were FIXED (ML-DSA/SLH-DSA hash-variant context params; SSL3/TLS key-and-mac NULL
phKey).

**Status (2026-05-30 follow-up session):**
- ✅ **Fixed & verified vs real backend:** A1 (in-flight-aware eviction), B1
  (generic Hash-ML-DSA/SLH-DSA), **B2 (message-init GCM/CCM param)**, **C2 (legacy
  PBE/PBA: registry gap + generic generate-key `pInitVector` writeback)**, **D1
  (bouncyhsm 3.0-interface fallback — `C_SessionCancel` reachability)**, **D2
  (AES-GMAC param: registry mis-classification)**. Plus the earlier ML-DSA + TLS
  key-and-mac fixes. **Every mechanism-transparency regression from the sweep is
  now fixed.**
- 📐 **ADR + staged plan:** A2 (backend process isolation — ADR-0007). Multi-day;
  not rushed into the correctness-critical path. The only remaining open work item.
- 📌 **Deferred TODO:** A3 (multi-client concurrency validation round — after the
  mechanism work).
- 📎 **Known-diff / optional:** C3 (wrap-key negative-path), C1 (unix socket — the
  user marked this review-later/optional).

Every mechanism-transparency regression the sweep surfaced has been fixed and
verified against a real backend — including D1 (a one-spot interface-loading bug,
not the operation-state rework first assumed), B2 (the 6-file message-init param
change on kryoptic), C2 (PBE/PBA on NSS), and D2 (a one-line GMAC registry
reclassification on bouncyhsm). The only remaining selected item is the
architectural one (A2), root-caused with a concrete ADR rather than rushed — its
own focused, reviewable change to
the proxy's correctness-critical
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

- **B2. Message-based API INIT param** — ✅ **FIXED (2026-05-30)**. PKCS#11 v3.0
  passes the AEAD params (`CK_GCM_MESSAGE_PARAMS`) to `C_MessageEncryptInit`, but
  the shim read the mechanism with the CLASSIC `gcm` shape (`CK_GCM_PARAMS`) — the
  same `CKM_AES_GCM` type is shared with single-shot encryption, so the param
  shape can't be inferred from the type — and shipped the wrong struct → backend
  `CKR_MECHANISM_PARAM_INVALID`.
  **Fix (option B — DRY, reuses the message machinery; no new mechanism shape):**
  1. proto: `optional MessageParameter init_message_parameter` on
     `Message{Encrypt,Decrypt}InitRequest`.
  2. shim `read_message_init_mechanism`: on a recognised `CK_*_MESSAGE_PARAMS`
     (via `try_read_message_parameter`), send the mechanism TYPE only + the
     structured param; parameterless/Raw falls back to the classic `read_mechanism`.
  3. client/server thread the field (server converts proto→`MessageParameter`).
  4. `Pkcs11Backend::message_{encrypt,decrypt}_init` gain
     `init_param: Option<&MessageParameter>` (FfiBackend + MockBackend + test
     backends). `build_message_init_mechanism` reconstructs `CK_GCM/CCM/SALSA_…_
     MESSAGE_PARAMS` (boxed for a stable address; IV/tag/nonce/MAC buffers kept
     alive in the holder across the FFI call — same lifetime discipline as
     `FfiMechanism`).
  Verified: 3 FFI reconstruction unit tests + wave6 integration; **real kryoptic
  backend** — the 2 regressions (`test_message_encrypt_decrypt_aes_gcm`,
  `…rejects_decrypt_only_key`) now PASS == direct; `test_mech_message.py` 4/4 and
  `test_message_crypto.py` 11/11 outcomes match direct (0 regressions). The
  generated-IV-writeback test now fails IDENTICALLY to direct (a kryoptic
  limitation, previously masked by the param-invalid skip). Related: D2 (GMAC
  multipart) shares this surface.

## Tier C — minor / optional

- **C1. Unix-domain-socket transport for the shim/client** (optional). Today the
  client only dials `http://` (no unix connector) and the server binds TCP
  (`UnixListenerConfig` exists but is unwired) — so it needs BOTH ends. Value:
  on-host perf + `SO_PEERCRED` peer-auth; NOT a robustness fix (it would not have
  prevented the nss cascade, which was a supervisor crash-recovery bug). Low
  urgency.

- **C2. Legacy PBE `CK_PBE_PARAMS` (4 nss tests)** — ✅ **FIXED (2026-05-30)**.
  Two distinct gaps, not one: (A) `CKM_PBA_SHA1_WITH_SHA1_HMAC` (0x03C0) was not
  mapped to the `pbe` param shape → `CKR_MECHANISM_PARAM_INVALID` (2 tests). One-
  line registry add (it reuses `CK_PBE_PARAMS`; AGENTS.md §12.6). (B) the
  generated `CK_PBE_PARAMS.pInitVector` (spec: "receives the 8-byte IV") wasn't
  written back after `C_GenerateKey` (2 tests). `C_GenerateKey` had no
  mechanism-output path (unlike derive), so mirrored the `derive_key_with_output`
  precedent: `GenerateKeyResponse.mechanism_out` + a default-delegating
  `generate_key_with_output` trait method (FfiBackend reuses
  `call_object_with_mechanism_output`) + a client `generate_key_with_mechanism_out`
  + shim writeback via the existing generic `write_mechanism_output_params`. Added
  the missing `Pbe` arms to `output_params()` (backend) and
  `write_mechanism_output_params()` (shim) — the IV ONLY; the password/salt are
  never echoed back (AGENTS.md §4). This makes generate-key writeback **generic**:
  any future output-param keygen mechanism needs only an arm, no new RPC plumbing.
  Verified: 2 shim writeback unit tests + **real NSS** — all 4 tests pass,
  `test_pbe.py` 22/23 pass + 1 skip == direct, 0 regressions.

- **C3. softhsm2 wrap-key error code** — undersized AES wrap key →
  `CKR_GENERAL_ERROR` (proxied) vs `CKR_WRAPPING_KEY_SIZE_RANGE` (direct). Both
  reject (negative path). Confirm whether the proxied `C_CreateObject` of the
  undersized key is byte-identical to direct (the one unverified bit). Low.

## Tier-2 provider findings (2026-05-30 — opencryptoki/tpm2/bouncyhsm)

opencryptoki-master and tpm2: **0 regressions, PASS** (the supervisor crash-recovery
fix auto-recovers pkcsslotd/swtpm crashes). bouncyhsm: 832 regressions pre-fix,
now reduced to ~12: **513 (the largest cluster, D1)** eliminated by the
3.0-interface fallback (`C_SessionCancel`), and **87 (D2)** by the AES-GMAC
registry fix below; the remaining ~12 are MCT multiblock timeouts (known
proxy-latency class, a documented known-diff — not a transparency bug).

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
- **D2. AES-GMAC param** (87 `CKR_MECHANISM_PARAM_INVALID`) — ✅ **FIXED
  (2026-05-30)**. Root cause: `CKM_AES_GMAC` (0x108E) was mis-listed as
  **parameterless** in the registry, so `check_operation` locally rejected the
  IV/nonce parameter (`MECHANISM_PARAM_INVALID`) in the shim before it ever
  reached the backend. (Not multipart-specific — single-shot `test_aes_gmac`
  failed too; the IV is only at init.) BouncyHSM is the only backend that
  supports GMAC (kryoptic/others skip it), and it takes the bare IV bytes (the
  spec models `CK_GCM_PARAMS`, but the proxy must forward what the native module
  accepts). **Fix:** moved 0x108E from `parameterless` to the existing `iv`
  shape — a length-preserving verbatim passthrough of the parameter buffer, so
  the backend receives it byte-identically to a direct call (registry-only;
  AGENTS.md §12.6). Verified on real bouncyhsm: GMAC 418/418 outcomes == direct
  (411 pass + 7 skip), 0 regressions.
- MCT multiblock timeouts (~12) — known proxy-latency, already a known-diff class.

## Separate repo — pkcs11-check
See `docker/proxy-test/pool/pkcs11-check-backlog.md` (root repo): structured
per-call CK_RV trace, 10000× C_Initialize churn/exhaustion test, mid-file
daemon-restart handling.

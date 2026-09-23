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
- 🚫 **Deferred — superseded operationally:** A2 (backend process isolation — ADR-0007).
  Decided 2026-05-30 after a deep review: backend-crash isolation is handled by **running
  multiple daemon instances + sticky client routing + client reconnect**, not an in-process
  worker. The worker design (spec + ADR) is kept as a documented fallback. No code work.
- 📌 **Deferred TODO:** A3 (multi-client concurrency validation round — after the
  mechanism work).
- 📎 **Known-diff / optional:** C3 (wrap-key negative-path), C1 (unix socket — the
  user marked this review-later/optional).

Every mechanism-transparency regression the sweep surfaced has been fixed and
verified against a real backend — including D1 (a one-spot interface-loading bug,
not the operation-state rework first assumed), B2 (the 6-file message-init param
change on kryoptic), C2 (PBE/PBA on NSS), and D2 (a one-line GMAC registry
reclassification on bouncyhsm). A2 (the one architectural item) was analyzed in depth and then **deferred**: backend-crash
isolation is better handled operationally — multiple daemon instances + sticky client routing
+ client reconnect — than by an in-process worker, for this project's needs. See A2 below.

## Tier A — real correctness / robustness (production-relevant)

- **A1. In-flight-aware context eviction** — ✅ **FIXED (2026-05-30)**.
  `follow-up-inflight-eviction.md`. Per-context `in_flight` counter +
  `OperationGuard` taken once in the gRPC dispatch macro; eviction skips busy
  contexts. Verified: DH param-gen 2 failed → 6 passed at the default lease=30
  (plus a unit test). No per-handler churn.

- **A2. Backend process isolation** — 🚫 **DEFERRED (2026-05-30) — superseded by
  operational multi-daemon isolation.** Deep review concluded: an in-process worker does
  **not** make a backend crash transparent (PKCS#11 session/login/op state is un-serializable
  and dies with the backend regardless; the client must re-establish it either way), and its
  only unique wins (keeping the shared daemon's connections alive through a crash; killing a
  *hung* backend, `config.rs:138` orphaned thread) are **low value for this project**, which is
  fine with full restarts and client reconnection. Backend-crash isolation is instead achieved
  by **running multiple `pkcs11-proxy-ng` instances**, partitioning clients across them with
  **sticky** routing (a session is valid only on the daemon that created it — never round-robin
  per call), and letting the orchestrator restart a dead instance. The actual lever for the
  observed failure cascade is **client-side reconnect/re-open** (the shim already retries connects
  with backoff, `state.rs:597` `MAX_ATTEMPTS=10`; the `CKR_DEVICE_ERROR` cascade is the *client*,
  `client/src/error.rs:36`, mapping `Unavailable` while the daemon is down). The worker design is
  retained as a documented fallback: design spec `doc/plans/2026-05-30-backend-process-isolation-design.md`,
  decision record ADR-0007, full analysis `follow-up-backend-crash-isolation.md`. **No code work
  planned.**

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

- **B2. Message-based API parameter contract** — ✅ **FIXED (2026-08-06;
  supersedes the 2026-05-30 size-inferred path)**. PKCS#11 v3.0 passes
  `CK_*_MESSAGE_PARAMS` to MessageEncrypt/MessageDecrypt Init and later calls.
  These layouts share mechanism types with classic operations, so the active
  message operation is now bound to the registry-selected message shape and
  direction instead of guessing a struct from its byte size.
  **Fix (reuses the message machinery; no second parameter hierarchy):**
  1. proto: `optional MessageParameter init_message_parameter` on
     `Message{Encrypt,Decrypt}InitRequest`, plus the shared shape and outer
     pointer-class envelope/acknowledgements on the safe paths.
  2. shim `read_message_init_mechanism` derives GCM, CCM, or Salsa/ChaCha from
     the mechanism registry. `read_message_parameter_call_for_shape_with_memory`
     then enforces the exact client-native outer layout, pointer class,
     direction/stage semantics, bounded embedded extents, and non-aliasing.
     There is no Raw or classic-parameter fallback for a materialized message
     parameter; materialized non-NULL/nonzero unmodelled parameters fail closed.
  3. client/server validate and echo the independently derived shape, caller
     envelope, and structured variant before state or caller memory is updated.
  4. `Pkcs11Backend::message_{encrypt,decrypt}_init` gain
     `init_param: Option<&MessageParameter>` (FfiBackend + MockBackend + test
     backends). `build_message_init_mechanism` reconstructs `CK_GCM/CCM/SALSA_…_
     MESSAGE_PARAMS` in the provider's native ABI (boxed for a stable address;
     IV/tag/nonce/MAC buffers kept alive across the FFI call). Encrypt supports
     validated writeback, Decrypt is input-only, and Sign/Verify is empty-only.
  **Historical pre-supersession evidence (2026-05-30):** 3 FFI reconstruction
  unit tests + wave6 integration; **real kryoptic backend** — the 2 regressions
  (`test_message_encrypt_decrypt_aes_gcm`,
  `…rejects_decrypt_only_key`) now PASS == direct; `test_mech_message.py` 4/4 and
  `test_message_crypto.py` 11/11 outcomes match direct (0 regressions). The
  generated-IV-writeback test now fails IDENTICALLY to direct (a kryoptic
  limitation, previously masked by the param-invalid skip). Related: D2 (GMAC
  multipart) shares this surface. Those runs predate the 2026-08-06 pointer-safe
  contract and are not provider evidence for it; a fresh provider matrix is the
  next external gate.

## Tier C — minor / optional

- **C1. Unix-domain-socket transport for the shim/client** — ✅ **IMPLEMENTED
  (2026-05-30)**. Scope (per the review): a **local-user** transport (and
  ssh-forwardable); the multi-client production path stays TCP+mTLS. Auth is
  `peer_cred` (`SO_PEERCRED` kernel-verified uid → existing token policy) — the
  local-IPC equivalent of mutual auth; **no mTLS on the socket** (a Unix socket
  has no network to secure, and a cert proves key-possession not process
  identity). The PKCS#11 PIN (`C_Login`) remains the independent end-to-end key
  gate. **Server** (`main.rs`): multi-listener serve (TCP and/or UDS) under a
  shared watch-shutdown; `bind_unix_listener` removes a stale socket (never a
  non-socket), pins `0600` owner-only, removes the socket on exit; the old
  "reject until wired" guard is replaced by a parent-dir check. **Identity**
  (`request_identity`): a request carrying tonic's `UdsConnectInfo` → `PeerCred`
  (or `Unauthenticated` for `auth=none`; peer_cred with no creds fails closed),
  else the existing mTLS path; service carries `unix_auth_mode`. **Client**
  (`lifecycle.rs`): a `unix:` endpoint dials via `connect_with_connector` +
  `TokioIo<UnixStream>`; the shim's `PKCS11_PROXY_ENDPOINT=unix:/path` flows
  through unchanged. Verified: 4 `request_identity` unit tests + 2 runtime
  validation tests + **2 end-to-end UDS tests** (real socket: matching uid sees
  the slot; non-matching uid is filtered, proving the real peer uid is derived).
  Example: `examples/config-unix-local.toml`. (Pre-existing, unrelated:
  `mtls_authorization_test` fails on HEAD too — a TLS-cert/env issue in the
  sandbox, confirmed by stashing this work.)

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
  T20 addendum (2026-09-23): the "iv" mapping broke 3.x-style callers
  (freehsm-c, cryptoki 3.2), which pass a `CK_GCM_PARAMS` struct for GMAC:
  verbatim-forwarding the struct handed the backend stale client pointers
  and segfaulted the daemon (32 freehsm-c regressions, `CKR_DEVICE_ERROR`).
  Fix: new `gcm_compat` shape — buffers shorter than the struct still
  forward verbatim as IV bytes (BouncyHSM unchanged), struct-sized buffers
  are parsed as `CK_GCM_PARAMS`. Re-proofed on real freehsm-c (GMAC 32/32
  pass) and bouncyhsm (GMAC outcomes == direct).
- MCT multiblock timeouts (~12) — known proxy-latency, already a known-diff class.

## Separate repo — pkcs11-check
Tracked with the project's `pkcs11-check` parity tooling: structured
per-call CK_RV trace, 10000× C_Initialize churn/exhaustion test, mid-file
daemon-restart handling.

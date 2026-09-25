# ADR-0012: Gateway & Resilience Modes

## Status
**Proposed (2026-07-04; last revised 2026-08-05).**
Implemented locally, partially covered, and unreleased. Acceptance and public-release language require a
provenance-complete transparency matrix and public release evidence.
**Implemented locally:** (1) opt-in count-only pathological-population detection (`[resilience]`)
+ local Unix-socket metrics endpoint; (2) **G1 audit stream** — the tamper-evident
engine (SHA-256 hash chain, Ed25519-signed checkpoints, rotating sink, anchor,
directory `verify`), fail-closed emission for auth/session/PIN-admin and
key-lifecycle operations, audit metrics, and a **startup** backend-attestation
record; (3) **G2-PR1 identity/config hardening** (refuse-to-start on `policy` or
`allow_all_authenticated` + `auth="none"`; require `anonymous_principal` for
unauthenticated audit; reject writable config/module/audit-dir; per-slot
login-lock acquisition timeout); (4) **G2-PR2 authorization enforcement** —
mTLS leaf-SPKI identity keying (dual-accept DN transition), deny-default
authenticated policy with explicit allow-all override, audit-label-only
`anonymous_principal`, class/mechanism/extract grant model, opt-in extract-deny
on `C_WrapKey`/`C_WrapKeyAuthenticated`/
value-bearing `C_GetAttributeValue`; (5) **G2-PR3 rate/quota** — per-principal
in-flight cap + session quota (`CKR_SESSION_COUNT`) + per-slot failed-login budget,
opt-in via `[rate_limit]`; (6) **G3-PR1 per-object use-time authorization** —
opt-in `objects` allow-list keyed on `CKA_UNIQUE_ID`, enforced at the resolution
seam with constant-work-on-RV/audit/metric invisible denial (I1: NOT constant-latency
— first-access incurs backend UID fetch), v3.0+-gated (refuse-to-start on v2.40);
(7) **G3-PR2 `C_FindObjects` enumeration filtering** (confined principals never
receive handles for objects they cannot use); (8) **G3-PR3 authz completion** —
per-class + per-mechanism enforcement (config un-rejected), per-object extract
override, minted-object ACL inheritance, and the I2 session-only-metadata-cache
hardening; (9) **G1 data-plane audit** — opt-in (`[audit] data_plane = true`)
emission for sign/encrypt/decrypt/verify/digest, fail-open with reserved-capacity
admission (`channel_capacity`/`fail_closed_reserve`) so a data-plane flood cannot
starve fail-closed classes (C1 isolation), gap sentinel (`__AUDIT_GAP__`, chained +
tamper-evident) records dropped runs, and `verify` surfaces the dropped count.
**Not yet implemented / phased (see the §-notes below and the full-review gap
analysis 2026-07-06):** reconnect/hot-swap re-attestation; constant-latency
denial (documented I1 limit). **R2 attribute-coalesce is implemented locally** (see
Resilience § below). The G3 authorization model is substantially complete —
promote to **Accepted** after a transparency-matrix validation pass.

## Context

Ordinary/exact `C_WrapKey`, `C_WrapKeyAuthenticated`, and authenticated unwrap
audit completed outcomes through the same fail-closed KeyMgmt envelope. Exact
results contribute their embedded provider RV, including `CKR_BUFFER_TOO_SMALL`.
A transport/native-task failure has no provider RV and is audited as proxy
`CKR_FUNCTION_FAILED`; its original transport status is retained if audit accepts.
If audit rejects, the response is `CKR_FUNCTION_FAILED` and suppresses every
output channel (bytes, lengths, parameter/mechanism output, and created handle).
Records contain only the existing identity/method/session/RV/timing metadata.
Audit failure after native side effects retains the existing divergence contract.
Cancellation with detached native work still requires completion-owned auditing
in the separate lifecycle work. Exact native error effects remain a separate
correction gate. Authenticated parameters use ADR-0010's negotiated typed
output allowlist; native structure images and input-only remapped handles are
never returned. Fail-closed audit also suppresses that typed output envelope.

`pkcs11-proxy-ng` has one design persona today: a **transport** that forwards
within ADR-0010's explicit support/width limits. A second, distinct persona is requested by
would-be operators of the daemon as a shared, multi-client **access gateway** in
front of a token/HSM: audit of security-relevant operations, per-client
authorization beyond the coarse token ACL of ADR-0005, rate/quota controls, and
resilience against pathological workloads (e.g. a token holding thousands of
certificates sharing one `CKA_ID`, where a single "find my cert" explodes into
thousands of per-object round-trips).

These are exactly the non-functional gaps a security buyer raises: no audit
trail (NFR-4), no authorization model, no DoS/abuse controls, no secret-injection
model (NFR-2). They cannot be met by a pure transport. But bolting them on
unconditionally would break the ADR-0010 guarantee that an application cannot
distinguish the shim from the real module.

## Decision

1. **Every gateway/resilience capability is strictly opt-in and default-off.**
   Mandatory native-lifetime safety and the explicit v0.2 slot-event support
   limit below are outside this opt-in rule.
   With no `[audit]`, `[policy]`, or `[resilience]` configuration present, the
   daemon is byte-identical to today — same client-visible behavior, same
   `CK_RV`s, same backend call sequence. This is the same contract as
   `sanitize_inputs` (ADR-0010 §4) and is covered by local feature-off tests
   asserting byte-identical output; those tests are not a transparency matrix.
   Pure in-process
   observation (counters) that changes neither client-visible behavior nor the
   backend call sequence is permitted on the default path; anything that issues
   an extra backend call or alters a response stays behind its config gate.

2. **The capabilities are implemented locally in phases, each independently useful:**
   - **Resilience (implemented locally, first increment):** count-only detection of
     pathological object populations + a local, authenticated (Unix socket,
     mode 0600) metrics endpoint. Detection reads only values already in hand;
     it never issues an extra backend call.
     **R2 — context-scoped attribute coalescer (implemented locally, opt-in):** enabled by
     `[resilience] coalesce_attributes = true` (default off). Caches per-`(context,
     object, attribute)` backend results and serves repeated `C_GetAttributeValue`
     calls for the same triple from memory, eliminating backend round-trips for
     repeated reads. Properties: (a) **byte-identical on a hit** — the raw
     per-attribute byte sequence returned by the backend is stored verbatim and
     reconstructed identically; (b) **non-security attributes only** — V5
     value-bearing-secret attributes (`CKA_VALUE`, `CKA_PRIVATE_EXPONENT`, etc.)
     and `CKR_ATTRIBUTE_SENSITIVE` results are never cached; (c) **invalidated**
     on `C_SetAttributeValue`, `C_DestroyObject`, `C_Logout`, and session close;
     (d) **multi-client staleness limitation** — the cache is per logical client
     context; a mutation to a shared token object by a **different client context**
     is not observed, so the local cache serves stale data until session close or
     logout. This is the opt-in rationale: suitable for read-heavy, single-writer
     workloads (e.g. immutable certificate metadata); **not suitable** for
     multi-writer shared-token scenarios. Cross-context isolation (different
     identities having separate contexts) is enforced regardless of this setting.
     This addresses **REPEATED-read amplification** (same attribute, same object,
     same context); the N-distinct-object cert-storm collapse is R3 (dedup),
     still a follow-up.
     Observable via `pkcs11_proxy_attr_coalesce_hits_total` /
     `pkcs11_proxy_attr_coalesce_misses_total` at the metrics endpoint.
     Follow-up (not implemented): attribute prefetch (fetch a set of common attributes
     on first read to collapse one-at-a-time multi-attr reads into one round-trip;
     needs exact-output-prefetch design). R3 (not implemented): duplicate-object
     collapse (N-distinct-cert-storm mitigation).
   - **G1 — Audit stream:** a security-relevant event log (authenticated
     identity, method, slot/session, `CK_RV`, latency; object labels/IDs are
     hashed or omitted by default and are not fetched from the backend). Records
     are hash-chained (SHA-256), anchored across restart and rotation, and sealed
     by periodic Ed25519-signed checkpoints (record-count *and* time triggered).
     The daemon owns rotation (rename-then-new, never copytruncate). A `verify`
     command walks a whole log directory.
     **Tamper-evidence is bounded to signed-checkpoint coverage:** with a
     configured `signing_key`, history up to the last checkpoint is
     cryptographically tamper-evident; the unsigned anchor gives corruption
     detection for the post-checkpoint tail but is not proof against a writer who
     can rewrite both the record and the anchor. **Without a `signing_key` the
     chain is corruption-detecting only, not tamper-evident** (a directory-writer
     can recompute the SHA-256 chain and rewrite the anchor). A front-truncation
     below the oldest retained checkpoint is indistinguishable from legitimate
     pruning. Sink-failure policy is per class: **fail-closed** (reject the
     operation) for auth / key-management events. **Emission implemented locally covers
     auth/session/PIN-admin + key-lifecycle** (generate/derive/wrap/unwrap/
     create/destroy/copy) **and data-plane** (`C_Sign`/`C_Encrypt`/`C_Decrypt`/
     `C_Verify`/`C_Digest` — one record per completed operation, i.e. the
     single-shot ops and the multi-part `*Final` completions; the high-volume
     `*Update` steps are intentionally NOT emitted). Data-plane emission is
     **opt-in** via `[audit] data_plane = true` (default off). It uses a
     **reserved-capacity partition of the shared channel** — a DataPlane record is
     admitted only while the channel retains more than `fail_closed_reserve` free
     slots (of `channel_capacity`), so the fail-closed classes always have room: a
     data-plane flood cannot starve auth records (C1 isolation). When the reserve
     is reached or the channel is full the record is **dropped (fail-open)** and a
     **gap sentinel**
     (`method = "__AUDIT_GAP__"`, `class = system`, `dropped_count = N`) is
     chained as the next record, making the drop **tamper-evident** (removing
     or altering the sentinel breaks the hash chain). The `verify` command
     surfaces the total dropped count (`dropped_records` in `VerifyReport`;
     printed as the `dropped` line in CLI output). Drops are possible under
     sustained overload — that is the fail-open design. Audit records contain
     operational metadata only, never PINs, key material, or raw request
     payloads. Because fail-closed records are emitted after the backend result
     is known, an audit failure can reject the proxy operation after a backend
     side effect. `EventClass::Deny` remains reserved rather than emitted.
     The current key-lifecycle emission claim excludes KEM operations and
     completion after RPC cancellation. Mechanism admission on KEM does not add
     audit coverage. Outcome-audit parity for KEM remains separate work;
     DataPlane stays fail-open.
   - **G2 — Identity hardening + coarse authorization + rate/quota:**
     *Hardening (G2-PR1, implemented locally):* the daemon refuses to start when a
     policy or `allow_all_authenticated = true` is configured alongside an
     `auth="none"` listener; unauthenticated audit requires an
     `anonymous_principal`. It also bounds the per-slot login lock. With no policy,
     unauthenticated transport/dev mode remains allowed subject to listener
     safety configuration. `anonymous_principal` changes only its audit label,
     is never a policy grant, and does not relax those config guards.
     *Authorization enforcement (G2-PR2, implemented locally):* with an
     authenticated policy, an unknown/unmatched identity is **denied by
     default**; `allow_all_authenticated = true` is an explicit operator
     override for authenticated identities.
     mTLS identity uses the **leaf certificate's SPKI/fingerprint** as its primary
     key (not issuer-SPKI + a reversible subject DN string, which lets a pinned
     CA mint a colliding-subject cert), while dual-accepting legacy DN-keyed
     policy entries and logging the operator migration path. An unauthenticated
     peer carries **no** cross-peer A2 ownership isolation. **Coarse (slot-level)
     authorization is all-or-nothing
     per token — it grants full key USE and, for extractable keys, key
     EXTRACTION** (via `C_WrapKey` / value-bearing `C_GetAttributeValue`);
     class/mechanism and grant-level extract restrictions are implemented
     separately. Grant-level `extract = "deny"` covers `C_WrapKey` and
     value-bearing attribute reads without relying on PKCS#11 v3.0. Per-object
     allow-lists and per-object extract overrides require v3.0+
     `CKA_UNIQUE_ID`; a v2.40 token has no per-object controls.
     *Rate/quota (G2-PR3, implemented locally, opt-in via `[rate_limit]`):* enforced at the
     dispatch seam covering **both** the `impl_proxy_service!` macro path and the
     hand-written handlers, with per-principal fairness. The reject codes are
     **reconciled by kind** (2026-07-06 review): a transient per-principal
     **in-flight** cap returns gRPC `resource_exhausted` (retryable, same as the
     existing per-context cap); a per-principal **session** quota returns the
     spec-native **`CKR_SESSION_COUNT`** as a CK_RV (derived leak-proof count, so
     a client disconnect can never leak a reservation); a per-**slot** aggregate
     **failed-login** budget fast-rejects with `CKR_DEVICE_ERROR` after K PIN
     failures (indistinguishable from the existing login-lock timeout) to stop
     feeding the backend token's **shared PIN-lockout** counter (the proxy is one
     application to the token — the budget is per-slot AGGREGATE, not
     per-principal, by design). All three rejections are EXCLUDED from the
     backend-health failure counter (proxy-imposed, not backend faults) and are
     inert/byte-identical when `[rate_limit]` is absent. Throttling is normal
     backpressure, **not** an unreadiness signal (no k8s-readiness change).
     **Accepted limitations:** the session quota is a **soft** cap — its count is
     read lock-free, so N concurrent `open_session` calls for one principal may
     exceed the limit by up to N−1 (bounded by the in-flight/per-context caps); it
     is a fairness control, not a hard guarantee. The failed-login budget **resets
     on any successful login on the slot** — in a multi-tenant slot a legitimate
     tenant's success zeroes the shared counter, so the budget is defense-in-depth
     over the backend's own lockout (which likewise resets on success), not a hard
     bound on attacker attempts. Follow-ups (not implemented): a token-bucket
     requests/sec limiter if a workload needs it, and `CKR_DEVICE_MEMORY`-based
     memory quotas.
   - **G3 — Fine-grained authorization (G3-PR1 implemented locally: per-object use-time
     authz):** an opt-in per-object **allow-list** — a `[auth.policy]` grant may
     add `objects = [<CKA_UNIQUE_ID hex>,…]` to confine a principal to specific
     objects; absent → the principal may use all objects on tokens it is coarsely
     authorized for (byte-identical when unused). Enforced at the **object-handle
     resolution seam** (`resolve_session_and_object`/`_two_objects`/`_key`) so it
     covers every handle-consuming operation uniformly. A denial is
     **constant-work denial on the RV/audit/metric axes** (I1): the resolved
     handle is replaced with the same `CkObjectHandle(0)` sentinel the not-found
     path uses, so the backend returns the identical `CKR_OBJECT_HANDLE_INVALID` —
     same RV, no distinct audit/metric, no early-return, byte-for-byte
     indistinguishable from a nonexistent object (verified by test
     `per_object_gate_denied_object_identical_to_nonexistent`). The denial is NOT
     constant-latency: on the first access the gate fetches `CKA_UNIQUE_ID` from
     the backend (`C_GetAttributeValue`) and resolves the session's slot
     (`get_token_info`), after which the UID is cached per virtual handle.
     Because a PKCS#11 object handle is reusable and reassigned on reconnect,
     per-object authz keys on the immutable `CKA_UNIQUE_ID` (fetched once and
     cached per virtual handle — safe because it is immutable once set; I2 caveat:
     for token objects under cross-client backend object-number recycling, cache
     staleness could authorize against the wrong identity — tracking token-object
     cache invalidation is a deferred follow-up; session objects are safe via B2
     eviction-on-close). It is **restricted
     to v3.0+ tokens** that populate `CKA_UNIQUE_ID`: if any `objects` grant is
     configured against a backend reporting `< v3.0`, the daemon **refuses to
     start**; on a v3.0 token an object with an empty/absent `CKA_UNIQUE_ID` is
     **fail-closed** (denied). **Also implemented locally (G3-PR2/PR3):**
     `C_FindObjects` **enumeration-time filtering** (a confined principal's find
     results exclude objects it cannot use — the handle is never received; a
     server-side inner loop pulls past fully-filtered batches so `find` returns 0
     only on genuine exhaustion); **per-class and per-mechanism enforcement**
     (`classes`/`mechanisms` grants are enforced at the resolution seam / crypto
     `*Init` respectively — a class-mismatch is a constant-work handle-invalid
     denial, a mechanism-mismatch is `CKR_MECHANISM_INVALID`; the config
     refuse-to-start guard for these grants is removed); **per-object extract
     override** (an `objects` entry may be `{ id, extract }` so a principal can
     use-but-not-extract a specific object, deny-beats-allow); **minted-object ACL
     inheritance** (an object a principal generates/unwraps/creates this session is
     usable by its creating context regardless of the configured allow-list,
     per-context, evicted on handle removal); and the **I2 hardening** (object
     metadata — uid+class — is fetched in one round-trip and cached only for
     **session** objects; **token** objects are re-fetched every gate call, immune
     to cross-client backend handle recycling). **Remaining (non-G3):**
     constant-**latency** denial (the deny path's metadata fetch is a first-access
     timing difference — documented I1 limit); R2 attribute-coalesce is
     implemented locally (see Resilience § above).
     Data-plane audit emission and its fail-open channel are implemented locally (see G1
     above).

3. **Backend attestation is integrity/change-detection, not proof of identity.**
   A **startup record implemented locally** captures the module path + content hash, the
   library `C_GetInfo`, and the token's `C_GetTokenInfo` serial/model/firmware,
   emitted into the audit chain as a `System`-class record. It is explicitly
   **not** proof that the daemon fronts a specific HSM against a daemon-compromise
   adversary (the record is self-signed with an in-process key and the hash is
   computed by the same process). A stronger property would require TPM/remote
   attestation and an out-of-band expected hash; out of scope here.
   **Known gaps vs the full intent (phased, not yet implemented):** the startup
   payload does **not** yet include a config hash; and **re-attestation on
   token hot-swap is deferred** — the daemon's backend is an in-process FFI
   module with no reconnect hook, so a token swap that changes the serial under
   a running daemon is currently undetected. The cheap follow-up is to re-attest
   on the `device-removed`/`token-not-present` slot event the daemon already
   observes (the same signal used for authorization-cache invalidation), treating
   a serial mismatch as a fail-closed `System` event.

4. **Dependency discipline.** Signed checkpoints use `ed25519-dalek` with
   `default-features = false` (no `rand_core`): the daemon **signs** with a key
   loaded from a file or `systemd-creds`, and never **generates** keys
   (key generation is an offline operator step). This keeps the strict
   `deny.toml` (`multiple-versions = deny`) satisfied — no additional `getrandom`
   is pulled. `sha2` is already vendored.

## v0.2 native-lifetime amendment (2026-09-13)

**Selected contract; implementation/qualification pending.** The
[native ownership contract](../release/native-mechanism-ownership.md) requires
one provider-chain domain and unconditional last-owner protection on qualified
Linux GNU/musl x86_64/64-bit and x86/32-bit targets. Configured grace and stuck
thresholds govern proactive stopping; disabling gateway/resilience options
cannot authorize native-storage destruction without a private quiescence proof.

Shutdown seals admission, drains ordinary workers including supported
DONT_BLOCK waits, then performs exclusive native Finalize with retained owners
live. Blocking slot waits are unsupported, without polling. An independent
deadline controller can invoke the private return-aware raw `exit_group(70)`
even while a native call or Finalize holds a lifecycle/session lock. The
existing opt-in `std::process::exit(70)` path does not implement this contract.
No unsafe last Drop, cleanup callback, audit flush or reason formatting may
precede that mandatory stop; metadata notice is best effort and cannot delay it.

The stop provides ordinary failure status 70 under the linked environment
assumptions, not SIGABRT or an unconditional wall-clock termination guarantee.
The audit tail can be incomplete and token effects unresolved. Supervisors
need a policy covering ordinary nonzero exit, with rate-limit/manual-stop
exceptions; the library does not configure restart or global crash-dump policy.
Native implementation, final-owner/direct-backend tests and same-source native
GNU/musl/width receipts remain required before release.

## Consequences

- The transport persona (ADR-0010) is unchanged and remains the default. The
  gateway persona is additive and gated.
- G3's per-object authorization is honestly bounded to v3.0+ tokens; this is a
  documented capability limit, not a silent degradation. Handle-keyed
  authorization on v2.40 tokens was considered and rejected as unsound (handle
  reuse + reassignment on reconnect would rebind grants).
- The "invisible denial" and integrity-only attestation are deliberate,
  documented departures from strict transparency, permitted only in the opt-in
  gateway mode and recorded here so they are not mistaken for ADR-0010
  violations.
- Audit fail-closed classes can, by design, reject an operation when the audit
  sink cannot record it (e.g. disk full); this is the correct trade-off for
  security-relevant events and is scoped to those classes only.
- Relationship to prior ADRs: extends ADR-0005 (coarse authorization) toward a
  role/ACL model; preserves ADR-0002 (handle/session identity) and ADR-0003
  (error model); complements ADR-0007's multi-daemon isolation rather than
  replacing it.

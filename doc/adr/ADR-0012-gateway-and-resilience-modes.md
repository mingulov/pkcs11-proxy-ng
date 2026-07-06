# ADR-0012: Gateway & Resilience Modes

## Status
**Proposed (2026-07-04; last revised 2026-07-06).** Introduced incrementally.
**Landed:** (1) opt-in count-only pathological-population detection (`[resilience]`)
+ local Unix-socket metrics endpoint; (2) **G1 audit stream** — the tamper-evident
engine (SHA-256 hash chain, Ed25519-signed checkpoints, rotating sink, anchor,
directory `verify`), fail-closed emission for auth/session/PIN-admin and
key-lifecycle operations, audit metrics, and a **startup** backend-attestation
record; (3) **G2-PR1 identity/config hardening** (refuse-to-start on `policy`/
`allow_all_authenticated`/`audit` + `auth="none"`; reject writable config/module/
audit-dir; per-slot login-lock acquisition timeout); (4) **G2-PR2 authorization
enforcement** — mTLS leaf-SPKI identity keying (dual-accept DN transition),
deny-default flip + audit-only `anonymous_principal`, class/mechanism/extract
grant model, opt-in extract-deny on `C_WrapKey`/`C_WrapKeyAuthenticated`/
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
hardening. **Not yet landed / phased (see the §-notes below and the full-review gap
analysis 2026-07-06):** data-plane (sign/encrypt) audit emission + the fail-open
gap-sentinel + its separate channel; reconnect/hot-swap re-attestation; R2
attribute-coalesce (perf); constant-latency denial (documented I1 limit). The G3
authorization model is substantially complete — promote to **Accepted** after a
transparency-matrix validation pass.

## Context

`pkcs11-proxy-ng` has one design persona today: a **transport** that forwards
verbatim and synthesizes nothing (ADR-0010). That persona is correct and must
be preserved. But a second, distinct persona is repeatedly requested by
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
   With no `[audit]`, `[policy]`, or `[resilience]` configuration present, the
   daemon is byte-identical to today — same client-visible behavior, same
   `CK_RV`s, same backend call sequence. This is the same contract as
   `sanitize_inputs` (ADR-0010 §4) and is enforced by a policy-OFF shard of the
   transparency matrix asserting byte-identical output. Pure in-process
   observation (counters) that changes neither client-visible behavior nor the
   backend call sequence is permitted on the default path; anything that issues
   an extra backend call or alters a response stays behind its config gate.

2. **The capabilities ship as phases, each independently useful:**
   - **Resilience (shipped, first increment):** count-only detection of
     pathological object populations + a local, authenticated (Unix socket,
     mode 0600) metrics endpoint. Detection reads only values already in hand;
     it never issues an extra backend call. Follow-ups (opt-in): session-scoped
     attribute prefetch to coalesce round-trips, and duplicate-object collapse.
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
     operation) for auth / key-management events. **Currently shipped emission
     covers auth/session/PIN-admin + key-lifecycle** (generate/derive/wrap/unwrap/
     create/destroy/copy). High-volume data-plane (`C_Sign`/`C_Encrypt`) emission
     — with a **fail-open** path, an explicit **gap sentinel**, a surfaced
     dropped-record counter, and a **separate channel from the fail-closed
     classes** (so a data-plane flood cannot starve auth records) — is a planned
     follow-up, NOT yet shipped.
   - **G2 — Identity hardening + coarse authorization + rate/quota:**
     *Hardening (G2-PR1, shipped):* the daemon refuses to start when a
     policy / `allow_all_authenticated` / audit is configured alongside an
     `auth="none"` listener, and bounds the per-slot login lock. *Authorization
     enforcement (G2-PR2, planned):* an unknown/unmatched identity is **denied by
     default** — which requires folding the **three** current
     unauthenticated/`allow_all_authenticated`⇒allow paths into one deny-default
     core (`TokenPolicy::allows` Unauthenticated + `allow_all_authenticated` +
     `slot_is_authorized`'s enforcement short-circuit), not just one.
     mTLS identity must key on the **leaf certificate's SPKI/fingerprint** (not
     issuer-SPKI + a reversible subject DN string, which lets a pinned CA mint a
     colliding-subject cert); this is a restructure of the DN-string identity key
     and needs a policy-file migration path. An `anonymous_principal` for an
     unauthenticated-but-audited listener is **audit-identity only** — deny-default
     for authz, forbidden from *all* grants, and carries **no** cross-peer A2
     ownership isolation. **Coarse (slot-level) authorization is all-or-nothing
     per token — it grants full key USE and, for extractable keys, key
     EXTRACTION** (via `C_WrapKey` / value-bearing `C_GetAttributeValue`);
     per-object / per-mechanism / extract restriction is G3 (v3.0+ only), so a
     v2.40 token gets coarse-only. An `extract-deny` coarse sub-gate on
     `C_WrapKey` + value-bearing attribute reads is a candidate for G2 itself.
     *Rate/quota (G2-PR3, shipped, opt-in via `[rate_limit]`):* enforced at the
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
     bound on attacker attempts. Follow-ups (not shipped): a token-bucket
     requests/sec limiter if a workload needs it, and `CKR_DEVICE_MEMORY`-based
     memory quotas.
   - **G3 — Fine-grained authorization (G3-PR1 shipped: per-object use-time
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
     **fail-closed** (denied). **Now also shipped (G3-PR2/PR3):**
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
     to cross-client backend handle recycling). **Remaining (non-G3):** data-plane
     (sign/encrypt) audit emission + its separate fail-open channel; R2
     attribute-coalesce (perf); constant-**latency** denial (the deny path's
     metadata fetch is a first-access timing difference — documented I1 limit).

3. **Backend attestation is integrity/change-detection, not proof of identity.**
   A **startup** record (shipped) captures the module path + content hash, the
   library `C_GetInfo`, and the token's `C_GetTokenInfo` serial/model/firmware,
   emitted into the audit chain as a `System`-class record. It is explicitly
   **not** proof that the daemon fronts a specific HSM against a daemon-compromise
   adversary (the record is self-signed with an in-process key and the hash is
   computed by the same process). A stronger property would require TPM/remote
   attestation and an out-of-band expected hash; out of scope here.
   **Known gaps vs the full intent (phased, not yet shipped):** the startup
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

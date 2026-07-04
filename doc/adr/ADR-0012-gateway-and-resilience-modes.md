# ADR-0012: Gateway & Resilience Modes

## Status
**Proposed (2026-07-04).** Introduced incrementally. The first increment —
opt-in, count-only pathological-population detection (`[resilience]`) plus a
local Unix-socket metrics endpoint — is implemented. The audit stream (this
ADR's G1) is the next increment. Promote to **Accepted** as the phases land.

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
   - **G1 — Audit stream:** a tamper-evident, security-relevant event log
     (authenticated identity, method, slot/session, `CK_RV`, latency; object
     labels/IDs are hashed or omitted by default and are not fetched from the
     backend). Records are hash-chained (SHA-256), anchored across restart and
     rotation, and sealed by periodic Ed25519-signed checkpoints. The daemon
     owns rotation (rename-then-new, never copytruncate). A `verify` command
     walks a whole log directory. Sink-failure policy is per class:
     **fail-closed** (reject the operation) for auth / key-management / deny
     events; **fail-open + an explicit gap sentinel + a dropped-record counter**
     for high-volume data-plane events.
   - **G2 — Identity hardening + coarse authorization + rate/quota:** when any
     policy is configured, the daemon refuses to start on an unauthenticated
     listener, and an unknown/unmatched identity is **denied by default**
     (superseding the legacy allow-for-unauthenticated shortcut). mTLS identity
     is keyed on the issuer's SPKI/fingerprint plus subject, not a reversible DN
     string. Rate/quota is enforced at the dispatch seam (not a transport
     layer), with per-principal fairness; quota rejections use spec-native RVs
     (`CKR_SESSION_COUNT`, `CKR_DEVICE_MEMORY`) and are excluded from the
     backend-health failure counter.
   - **G3 — Fine-grained authorization:** use-time authorization on every
     handle-consuming operation and on every handle-minting operation (not
     enumeration filtering alone), including a per-**attribute** check so that
     reading value-bearing secret attributes is gated as extraction. Denials
     return each function's own documented `CK_RV`, and a hidden object is
     **indistinguishable from a nonexistent one** — same return code, same
     latency, no backend call, no distinct audit/metric signal — to avoid an
     existence oracle. Because a PKCS#11 object handle is reusable and is
     reassigned on reconnect, per-object authorization keys on the immutable
     `CKA_UNIQUE_ID` and is therefore **restricted to v3.0+ tokens** that
     populate it; v2.40 tokens receive coarse (slot/token/class/mechanism)
     authorization only.

3. **Backend attestation is integrity/change-detection, not proof of identity.**
   A startup record captures the module path + content hash, the token's
   `C_GetTokenInfo` serial/model/firmware, and the config hash, signed into the
   audit chain; re-attestation on reconnect is mandatory and a serial mismatch
   is a fail-closed event. This detects a swapped `.so` or token against a
   running daemon. It is explicitly **not** a proof that the daemon fronts a
   specific HSM against a daemon-compromise adversary (the record is self-signed
   with an in-process key and the hash is computed by the same process). A
   stronger property would require TPM/remote attestation and an out-of-band
   expected hash; that is out of scope here.

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

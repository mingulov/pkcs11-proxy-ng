# ADR-0009: Per-request context ownership

**Status:** Accepted (2026-06-05)
**Relates to:** ADR-0005 §4 (Phase-1 authorization model), ADR-0002 §3
(client-context identity), ADR-0007 / A2 backend isolation (deferred)

## Context

A logical client is identified on the wire by a `client_context_id` string,
assigned by the daemon at `C_Initialize` and echoed back on every subsequent
RPC. The caller's authenticated **identity** (mTLS certificate subject, Unix
peer-credential uid, or "unauthenticated") was derived once, at
`C_Initialize`, and stored with the context. Later RPCs were trusted purely on
the `client_context_id` they presented.

That makes `client_context_id` an **unauthenticated bearer token**: any peer
that can reach the daemon's socket and learn (or guess) another client's
context id could drive that client's context — list its authorized slots, open
sessions, and (once logged in by the legitimate owner) perform operations —
without ever presenting the owning identity. The id is not secret: it travels
in every request and is not bound to the transport that carries it. ADR-0005 §4
already states that authorization is a property of the *identity*, not of a
token handed back to the client, so trusting the id alone violates the intended
model.

## Decision

Re-bind the caller's transport identity to the context **on every RPC that
carries a `client_context_id`**, not only at `C_Initialize`.

A single enforcement point, `check_context_owner`, runs before any handler
logic:

1. Look up the identity stored for the presented context
   (`ContextManager::context_identity`).
2. Re-derive the caller's **live** identity from the current request's
   transport extensions via the existing `identity_from_request`
   (the same code path `C_Initialize` uses), using the daemon's configured
   `tcp_auth_mode` / `unix_auth_mode`.
3. If the context has a recorded identity and it does **not** equal the live
   identity, reject with gRPC `PermissionDenied`. A context with no recorded
   identity, or one that does not exist, passes this gate — the handler then
   returns the proper PKCS#11 `CK_RV` (e.g. `CKR_CRYPTOKI_NOT_INITIALIZED`),
   so the gate never masks a normal not-initialized result as a permission
   error.

The comparison is the canonical string form of `AuthenticatedIdentity`
(`Display`/`FromStr` are inverses), so `uid=1000`, `x509:issuer=…;subject=…`,
and `unauthenticated` all compare exactly. The decision is a pure function,
`context_owner_allowed`, that is unit-tested in isolation; the async wrapper
composes it with the already-tested identity derivation.

Enforcement is applied uniformly: the generated dispatch macro calls it for
every `$name` RPC, and each hand-written context-bearing handler
(`get_slot_list`, `get_slot_info`, `get_token_info`, `get_mechanism_list`,
`get_mechanism_info`, `open_session`, `close_all_sessions`, `init_token`)
calls it as its first statement. `get_backend_interfaces` carries no
`client_context_id` (mechanism-registry discovery) and is exempt;
`initialize` is the call that *binds* the identity and so precedes the gate.

## Alternatives considered

- **tonic interceptor.** A transport-layer interceptor cannot decode the
  per-RPC request type to read `client_context_id`, and would have to duplicate
  identity derivation. Rejected in favour of one typed helper at the dispatch
  boundary, which keeps the check next to the handlers it guards.
- **Make `client_context_id` an unguessable secret/capability.** Hardening the
  token still leaves it a bearer credential and does not bind it to the
  authenticated transport; weaker than checking identity directly.
- **Defer to backend-per-client isolation (A2 / ADR-0007).** That work is about
  *crash* isolation and is deferred; it does not address an in-process identity
  confusion and would not close this gap on the shared-backend Phase-1 daemon.

## Consequences

- A stolen or guessed `client_context_id` is useless without also presenting
  the owning transport identity. On an authenticated transport (mTLS / Unix
  peer-cred) this closes the bearer-token gap. On an `unauthenticated`
  transport all callers share the `unauthenticated` identity, so the gate is a
  no-op there — by design; isolation on an unauthenticated socket is out of
  scope for Phase 1.
- One extra `DashMap` lookup plus identity derivation per RPC. Both are
  in-memory and cheap relative to a backend FFI call.
- This enforces **identity** ownership per request. It does **not** re-evaluate
  the token-access *policy* on every request — whether to re-check
  `slot_is_authorized` in crypto/object handlers (revocation latency) remains
  the separate M14 decision, which now has the per-request identity it needs.
- Tested by `context_owner_allowed` unit cases (matching / mismatched
  peer-cred, unauthenticated-claiming-authenticated, exact mTLS match) and the
  end-to-end mTLS authorization tests (a certificate identity discovers and
  opens a session on its authorized slot; a non-matching certificate is
  filtered).

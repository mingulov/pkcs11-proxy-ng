# Async Persistence Decision Record

**Date:** 2026-03-14
**Status:** Decided (Phase 1: Option B — polling only)

## Context

PKCS#11 3.2 introduces three async operation management functions:

- **C_AsyncComplete** — polls whether an async operation (returning
  `CKR_PENDING`) has finished, and retrieves the result.
- **C_AsyncGetID** — persists an async operation past `C_Finalize` and session
  close, returning a `CK_ULONG` identifier that another client instance can
  use to reconnect after `C_Initialize`.
- **C_AsyncJoin** — reconnects to a persisted async operation using the ID
  from `C_AsyncGetID`, rebinding a new output buffer.

The persistence semantics of `C_AsyncGetID` and `C_AsyncJoin` conflict with
ADR-0002 Section 10, which states that `C_Finalize` tears down the logical
client instance immediately — closing all sessions, invalidating all virtual
handles, and releasing all state.

## Options Considered

### Option A: Keep async as stubs
Leave all three functions returning `CKR_FUNCTION_NOT_SUPPORTED`.

- **Pro:** Zero complexity, no ADR conflict.
- **Con:** Applications expecting async support get nothing. Blocks PQC key
  generation on slow HSMs that return `CKR_PENDING`.

### Option B: Polling only, no persistence (chosen)
Implement `C_AsyncComplete` for real (polls `CKR_PENDING` → result).
`C_AsyncGetID` returns `CKR_STATE_UNSAVEABLE`. `C_AsyncJoin` returns
`CKR_SAVED_STATE_INVALID`.

- **Pro:** Covers the primary use case (waiting for slow HSM operations like
  PQC key generation). Spec-compliant — `CKR_STATE_UNSAVEABLE` is the
  defined way for a module to say "I cannot persist this operation."
  No ADR-0002 conflict.
- **Con:** No cross-finalize resumption. Applications that rely on
  `C_AsyncGetID`/`C_AsyncJoin` for operation handoff will get refusal codes.

### Option C: Full async persistence
Implement all three functions with a daemon-global "detached async operation
store" that outlives logical client instances. `C_AsyncGetID` moves operations
from the context to the detached store. `C_AsyncJoin` moves them back.

- **Pro:** Full spec compliance. Enables cross-process HSM operation handoff.
- **Con:** Significant new complexity — daemon-global store, identity matching
  across contexts, TTL management, backend cancellation on expiry. Requires
  ADR-0002 amendment defining persistent operation semantics.

## Decision

**Option B** for the current phase. This provides the real-world value
(polling for `CKR_PENDING` on slow operations) without the architectural
complexity of cross-finalize persistence.

### ADR-0002 Amendment

Add to ADR-0002 Section 8 (Multi-Part Operation State):

> Async operation state (`CKR_PENDING` results) is stored server-side within
> the logical client instance's session. Pending operations are polled via
> `C_AsyncComplete`. Async operations do NOT survive `C_Finalize` or context
> teardown — they are cancelled. `C_AsyncGetID` returns
> `CKR_STATE_UNSAVEABLE` because the proxy does not support persistent async
> operations in this phase.

### Return Codes

| Function | Return | Rationale |
|----------|--------|-----------|
| `C_AsyncComplete` | Real result or `CKR_PENDING` | Transparent proxy passthrough |
| `C_AsyncGetID` | `CKR_STATE_UNSAVEABLE` | The proxy does not support persistent async operations in this phase |
| `C_AsyncJoin` | `CKR_SAVED_STATE_INVALID` | For a well-formed call: no persisted async state can exist under this design |

**Error code discipline:**
- `CKR_STATE_UNSAVEABLE` — returned by `C_AsyncGetID` because the proxy
  cannot persist async operations. This is the spec-defined refusal.
- `CKR_SAVED_STATE_INVALID` — returned by `C_AsyncJoin` for any well-formed
  call because `C_AsyncGetID` never succeeds, so no valid persisted state
  can ever exist to join.
- `CKR_ARGUMENTS_BAD` — reserved for actual ABI/input errors only (e.g.,
  null/invalid `pFunctionName`, invalid pointer usage, malformed request).
  Never used to indicate "persistence unsupported."

## Future Extension Path

If a real need for cross-finalize persistence arises (e.g., a vendor HSM that
requires operation handoff across client restarts), implement Option C:

1. Amend ADR-0002 to define a "detached async operation store" at the daemon
   level, keyed by `(auth_identity, operation_id)`.
2. Define TTL and cancellation semantics for detached operations.
3. Implement `C_AsyncGetID` to move operations from context to detached store.
4. Implement `C_AsyncJoin` to rebind operations from detached store to a new
   context, with identity validation.

This is a backward-compatible extension — changing `CKR_STATE_UNSAVEABLE` to
a real ID is invisible to applications that handle the refusal correctly.

## References

- OASIS PKCS#11 3.2 spec: `asynchronous_function_management_functions.md`
- ADR-0002: Handle and Session Identity Model (Section 8, 10)
- Design spec: `docs/superpowers/specs/2026-03-14-pkcs11-3x-functions-design.md`

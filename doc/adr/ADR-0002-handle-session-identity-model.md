# ADR-0002: Handle and Session Identity Model

## Status

Implemented

**v0.2 scope amendment:** one logical client in one trusted security domain
per daemon/provider instance. Restart that instance before switching independent
clients or domains; `max_contexts = 1` is an admission guardrail, not an isolation
fix. The context model below describes implemented mechanisms and design goals;
it does not establish multi-client privacy or authentication-state isolation.
That work is deferred to [v0.3](../release/v0.3.0-scope.md).

The [native ownership contract](../release/native-mechanism-ownership.md)
is implemented, with current-candidate qualification separate from historical
acceptance records. Its lifecycle, width and stop requirements remain binding.

## Context

PKCS#11 defines behavior in terms of an **application**: `C_Initialize` and
`C_Finalize` bracket an application's use of the library, login state is shared
across all sessions an application holds with a given token, and
`C_CloseAllSessions` closes only that application's sessions. These semantics
assume a process-local shared library where "application" maps naturally to "OS
process."

A remote proxy breaks that assumption. Multiple remote clients share one daemon
process, so neither the daemon process boundary nor a raw network connection is
a correct substitute for the PKCS#11 application boundary. Three naive mappings
were considered and rejected:

- **Daemon-global shared state.** One handle namespace for all clients violates
  per-application isolation. `C_CloseAllSessions` from one client would close
  another client's sessions. Login state from one client would leak to another.

- **Raw transport connection = application.** Ties PKCS#11 state to TCP/gRPC
  connection lifetime. A transient network interruption becomes an
  application-visible session loss. Creates a denial-of-service path through
  connection resets.

- **mTLS identity = application.** Too coarse when multiple processes on one
  machine share a certificate, or when replicas of a service use the same
  credential. A certificate subject is an authorization identity, not a safe
  session-ownership key.

Comparable remote or service-backed PKCS#11 systems avoid all three:

- **Legacy `pkcs11-proxy` designs** prove the client-module plus remote-server
  shape, but do not justify tying PKCS#11 state ownership to a raw network
  connection.
- **Fortanix DSM** virtualizes slots and scopes key visibility by application
  credential, separating authorization identity from raw PKCS#11 session state.
- **Entrust nShield WSOP** uses mTLS for authentication and virtual
  partitioning for tenancy, but does not equate a transport connection with a
  PKCS#11 session boundary.
- **AWS CloudHSM** distinguishes ephemeral session keys from durable token
  keys, accepting that some state is connection-local while other state is
  persistent.

The recurring pattern is: preserve isolated per-caller PKCS#11 state through a
logical abstraction above the raw transport, even when backend lifecycle or
token connectivity is shared underneath.

## Decision

### 1. Logical Client Instance Model

The proxy introduces a **logical client instance** as the server-side
equivalent of a PKCS#11 application. All session, handle, and login state is
scoped to a logical client instance rather than to a transport connection,
daemon process, or mTLS certificate.

Slot-event pending flags remain an explicit exception: logical clients compete
for the one native application's source. Logical Initialize neither creates
nor clears an independent per-client bitmap. This is not full native
per-application event equivalence or a lossless event queue.

### 2. Backend Module Lifecycle

The daemon owns backend module lifecycle globally and manages it with reference
counting:

- The daemon calls `C_Initialize` on the backend module once, at daemon startup
  or on first client arrival.
- Each new logical client instance increments a daemon-side reference count.
- `C_Finalize` on the backend module occurs only when the daemon shuts down or
  the last logical client instance disconnects (implementation may choose to
  keep the module loaded for fast re-attach).
- Client-initiated `C_Initialize` and `C_Finalize` operate on the logical
  client instance, not on the backend module directly.

### 3. Logical Client Instance Lifecycle

When a client begins using the daemon (via the shim's `C_Initialize` or a
native client's explicit connect), the daemon creates a logical client instance
and returns an opaque `client_context_id`. Every subsequent request from that
client carries this ID.

- **Shim behavior:** The shim creates one logical client instance per
  successfully initialized shim module instance in an application address space.
  Under normal PKCS#11 usage this is effectively one PKCS#11 application
  context per process. The generic PKCS#11 shim does not expose multiple
  logical contexts within one application in Phase 1.
- **Native client behavior:** A native Rust/gRPC client may open multiple
  logical client instances over a single shared gRPC channel. This supports
  applications that need explicit intra-process isolation (e.g., a server
  multiplexing independent end-user workflows).

### 4. Slot Identity

Phase 1 exposes **daemon-virtual slot IDs** to clients.

- The daemon may preserve backend slot IDs internally, but the client-visible
  slot namespace is owned by the daemon.
- Client-visible slot IDs are stable for the lifetime of one daemon process and
  one unchanged backend configuration.
- There is **no** guarantee that a slot keeps the same numeric ID across daemon
  restart, backend reconfiguration, or token topology changes.
- Authorization policy and operator configuration should target stable token
  selectors (for example PKCS#11 URI fragments, token serials, or token labels),
  not raw numeric slot IDs.

The server distinguishes `VirtualSlotId` and `BackendSlotId` without implicit
conversions. Session ownership, token metadata, logical login state, login
serialization, and failed-login budgets use backend slots.
Only wire-facing slot arguments/results use virtual slots; native provider
calls receive the explicitly unwrapped backend identifier. This distinction
also applies when a virtual slot number equals another native slot number.

On successful `C_GetSessionInfo`, the provider's reported slot must match the
session's recorded backend owner and have a virtual mapping. An inconsistent
or unmapped provider slot is a provider-contract failure: return
`CKR_DEVICE_ERROR` without session information. Otherwise translate the slot
and preserve every other provider field. Provider errors pass through unchanged.
Audit session events retain the virtual slot namespace used by slot requests.

### 5. Handle Namespaces


`CK_SESSION_HANDLE` and `CK_OBJECT_HANDLE` values exposed to the client are
**virtual** and scoped to the logical client instance:

- The daemon maintains a bidirectional mapping between virtual handles (seen by
  the client) and backend handles (used with the real PKCS#11 module).
- Backend handles are never exposed to any client.
- Virtual handle values are generated independently per logical client instance,
  so handles from different clients never collide and cannot be used
  cross-instance.
- Session-object handles are valid only while the owning session is open.
  Token-object handles with known token classification remain valid within
  the logical client instance while the underlying object exists, but become
  invalid on context teardown or daemon restart. After successful `C_CopyObject`,
  classification uses the copy's actual `CKA_TOKEN` when readable, otherwise
  retaining a valid explicit template value. If lifetime cannot be established,
  native success is preserved with a session-scoped virtual handle; it can
  expire on copying-session close even if the native
  object persists. This fallback is a documented metadata limit.

### 6. Login State

Login state is scoped to **logical client instance + token**:

- `C_Login` on a session affects the login state of all sessions that the same
  logical client instance holds with that token, matching the PKCS#11 spec's
  per-application semantics.
- `C_Logout` from any session in the logical client instance returns all of that
  instance's sessions with the token to the public state.
- Independence of login state across logical clients is a v0.3 requirement,
  not a v0.2 guarantee. A shared native provider has authentication state beyond
  the proxy's per-context bookkeeping, even if clients use distinct identities.

**Backend-authoritative login (supersedes ADR-0008).** After local authorization,
handle, user-type and configured login-budget checks, `C_Login` and
`C_LoginUser` attempts are forwarded even when this or another logical client
holds the slot login. The backend determines whether to revalidate the PIN and
which return value to produce, including `CKR_PIN_INCORRECT` or an `ALREADY`
variant. The proxy must not assume that an already-logged-in backend ignores
the presented PIN. An `ALREADY` result establishes no logical login; successful
ordinary login records the requesting context's login state. Context-specific
login does not establish ordinary per-slot login state.

The holderless-but-logged-in reconciliation path remains an explicit exception:
an `ALREADY` result with no live logical holder triggers one backend logout and
one login retry, as specified below. Operators must account for the shared
native token login state; independent per-tenant native login environments
require separate provider processes.

**Per-slot login serialization (M5).** Session resolution, each native login
attempt and its logical-state update use the per-slot login lock
(`ContextManager::slot_login_lock`, one `tokio::sync::Mutex` keyed by slot id).
Concurrent attempts on one slot are serialized; the second attempt still
reaches the backend and receives its verdict. Serialization does not promise
exactly one native `C_Login` across two requests. The holderless reconciliation
path releases the lock across logout and reacquires it for the checked retry.
Login attempts on different slots use different locks.

### 7. Session Cleanup

`C_CloseAllSessions(slotID)` closes only the sessions opened by the calling
logical client instance for the specified slot. Sessions belonging to other
logical client instances are not affected.

When all sessions a logical client instance holds with a token are closed
(whether individually, via `C_CloseAllSessions`, or via context teardown), that
instance's login state for that token reverts to public.

**Last-context-out backend logout (D6(2)/D9-proxy).** The shared backend token
is logged out exactly when the last logical holder releases it: explicit
`C_Logout`, last-session close (individual or `C_CloseAllSessions`), and
context teardown (`C_Finalize`, lease eviction) each perform a REAL backend
`C_Logout` when — rechecked under the per-slot login lock — no live logical
client instance still holds login for the slot. The logout rides a still-open
session (the departing context's own when available, else any live session on
the slot) and runs before that context's backend sessions close. It never
blocks: lock contention defers to the holder, which is itself establishing
login consistency. Together with backend-authoritative login (D6(3)), this
bounds the backend-logged-in window to the live-holder lifetime, so every new
login PIN-verifies against the token.

### 8. Multi-Part Operation State

Active multi-part operation state (sign, verify, encrypt, decrypt, digest,
find) is stored server-side within the logical client instance's session. This
state dies with session close or context expiry. No operation state survives
transport reconnect if the session is lost.

Native FfiBackend currently inherits unsupported `C_AsyncComplete`; the earlier
polling decision is future intent, not implemented native support. `CKR_PENDING`
must retain the complete entered frame and affected owners until explicitly
supported terminal completion, full cancellation or successful session/module
teardown proves memory retirement. Logical context removal alone proves none
of those. Cross-finalize persistence is not supported; AsyncGetID/AsyncJoin
retain their documented refusal contract. See
[the async decision](async-persistence-decision.md).

### 9. Transport Reconnect and Lease

A transient gRPC reconnect does not automatically destroy logical client
instance state:

- The client stores its `client_context_id` in memory.
- On reconnect, the client presents the `client_context_id` to resume its
  logical client instance.
- If authentication is enabled, the resumed transport must authenticate as the
  same identity that originally created the context.
- The daemon maintains a **lease window** for each logical client instance. If
  the client reconnects within the lease window, all sessions, handles, and
  login state remain valid.
- If the lease expires without reconnect, the daemon tears down the logical
  client instance: all sessions are closed, all virtual handles are
  invalidated, and login state is released.
- Operations attempted against an expired context return
  `CKR_SESSION_HANDLE_INVALID` or `CKR_OBJECT_HANDLE_INVALID` as appropriate.

### 10. Finalization and Cleanup

State teardown follows a clear precedence:

1. **Explicit finalization:** Client calls `C_Finalize`. The daemon tears down
   the logical client instance immediately -- closes all sessions, invalidates
   all virtual handles, releases login state, decrements the backend reference
   count. Backend sessions are reaped only when unreferenced by any live
   context (refcount check, D9-proxy), and the backend login is released only
   on last-context-out (D6(2)). These checks describe the intended cleanup
   coordination; they do not establish multi-client isolation under native
   failures or cancellation.
2. **Transport disconnect:** The daemon starts the lease timer. If the client
   reconnects and presents a valid `client_context_id` before expiry, state is
   preserved. If the lease expires, teardown proceeds as in (1).
3. **Daemon restart:** All virtual handles and logical client instances are
   invalidated. No state survives daemon restart.

PKCS#11 excludes concurrent native Finalize and other Cryptoki calls, with an
explicit exception for a thread already blocking on C_WaitForSlotEvent. v0.2
does not support blocking mode and does not rely on a wrapper dispatch marker
to prove that exception applies. Supported DONT_BLOCK waits retain ordinary
lifecycle exclusion through settlement and never overlap native Finalize.
Logical client Finalize removes its context and arranges session cleanup; it
does not call module Finalize or implement native blocking-wait cancellation.
Context removal, RPC timeout and cancellation do not release native owners.
Native Finalize seals/drains the common domain; reinitialization requires a
successful old lifecycle epoch and full retirement of old workers/roots, with
checked fresh identity. Failed/uncertain teardown cannot reopen admission.

### 11. Backend Isolation Fallback Ladder

Not all backend PKCS#11 modules correctly isolate concurrent callers within a
single process. v0.2 uses one managed chain per embedding process and the
multi-daemon strategy of ADR-0007. The stronger alternatives below remain
deferred and are not available in-process safety guarantees:

- **v0.2: One logical client per daemon/provider instance.** Virtual handles
  and context ownership remain implemented mechanisms; they do not qualify
  shared-process multi-client isolation. Use one trusted domain and restart
  the daemon/provider before assigning it to an independent client or domain.

- **Deferred: Separate backend module instance per logical context.** Another
  `dlopen` handle or `RTLD_LOCAL` does not establish independent native globals,
  including aggregator dependencies. Independent project-managed construction
  is refused before loading under the v0.2 contract. A future shared-domain or
  namespace design would need its own identity/lifecycle proof.

- **Deferred: Separate worker process per logical context or principal.**
  Dedicated workers would provide an OS address-space boundary. This fallback
  is a design option, not an implemented v0.2 daemon feature or a guarantee
  of isolation in a shared external token.

Independent chains currently require separate processes. Another linked backend
runtime, unmanaged calls or shared downstream aggregator aliasing falls outside
the supported embedding contract. The registry is not cross-DSO enforcement.

### 12. Phase 1 Simplifications

Phase 1 adopts the full logical client instance model but with the following
constraints:

- **In-memory context only.** `client_context_id` is held in client process
  memory. There is no persistent storage of context IDs. If the client process
  exits or crashes, the context is gone.
- **No cross-restart resume.** Neither client process restart nor daemon restart
  preserves logical client instance state.
- **Callbacks not supported.** `C_OpenSession` requires `Notify == NULL_PTR`.
  Sessions opened with a non-null `Notify` are rejected with
  `CKR_FUNCTION_NOT_SUPPORTED` (or the most specific applicable error).
- **Async persistence not supported.** Native C_AsyncComplete is unsupported;
  polling remains future intent. C_AsyncGetID and C_AsyncJoin retain refusal
  codes. Pending memory cannot be freed on logical context teardown alone.
- **v0.2 `C_WaitForSlotEvent`: DONT_BLOCK only.** Blocking mode is locally
  FUNCTION_NOT_SUPPORTED, without polling. Sole-waiter and checked-width
  enforcement remain implementation gates; the native event source is shared.
- **`C_CloseAllSessions` is slot-scoped (implemented).** Session-to-slot
  tracking was added to `LogicalClientInstance`. `C_CloseAllSessions(slotID)`
  closes only this client's sessions for the target slot individually via
  `close_session` per handle, never forwarding to the backend's
  `C_CloseAllSessions`.

### 13. Open Questions

These are recorded for resolution during implementation or in follow-on ADRs:

- **Lease duration.** Should be configurable. Default value TBD (likely in the
  range of 30--300 seconds).
- **`client_context_id` generation.** Options include UUIDv4 or a
  cryptographically random opaque token. Must be unguessable to prevent context
  hijacking.
- **Blocking slot events or independent per-client event streams.** Deferred;
  neither is supplied by the v0.2 nonblocking scope.
- **Backend isolation tier selection.** Mechanism for configuration and
  auto-detection TBD.

## Consequences

### What becomes easier

- **Per-application state model.** Contexts represent session and handle
  ownership across the network boundary. Full multi-client isolation remains
  a v0.3 requirement; v0.2 is constrained to one logical client.

- **Transport resilience.** Transient network interruptions do not destroy
  application state. The lease mechanism provides a window for transparent
  reconnect without requiring the application to re-initialize, re-login, and
  re-open sessions.

- **Future multi-client work.** Logical contexts provide attachment points
  for policy, quotas and audit records. Safe coexistence of independent clients
  requires the v0.3 privacy and native-authentication work and its validation;
  it is not a v0.2 support claim.

- **Incremental isolation.** The fallback ladder lets the project start with the
  simplest (shared-process) backend model and escalate to stronger isolation per
  backend module as needed, without changing the client-facing protocol.

### What becomes harder

- **Server-side state management.** The daemon must maintain per-instance handle
  maps, session tables, login state, and lease timers. This is more complex than
  a stateless pass-through or a simple connection-scoped cleanup model.

- **Context ID security.** The `client_context_id` is a bearer token for
  session state. It must be generated with sufficient entropy and protected in
  transit (by mTLS) and at rest (in client process memory). A leaked context ID
  could allow another process to attach to a live session.

- **Lease tuning.** Too short a lease causes spurious context expiry on slow
  networks. Too long a lease causes the daemon to hold stale state and backend
  sessions for clients that are actually gone. The right default requires
  operational experience.

### What is deferred

- Callbacks and async sessions (PKCS#11 3.2).
- Persistent cross-restart resume of logical client instances.
- Blocking `C_WaitForSlotEvent` and independent per-client event streams.
- Fallback isolation tiers 1 and 2 (designed-for, not implemented in Phase 1).
- Cross-restart slot identity guarantees and hotplug semantics beyond the
  daemon-lifetime rule defined above.

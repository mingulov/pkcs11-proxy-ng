# ADR-0002: Handle and Session Identity Model

## Status

Proposed

**v0.2 P0 amendment (2026-09-13): selected contract; implementation pending.**
The [native ownership contract](../release/native-mechanism-ownership.md)
specifies one provider-chain domain, ordinary lifecycle exclusion for the sole
nonblocking slot waiter, checked widths/epochs and quiescent retirement. It
does not establish completed implementation or native-provider qualification.

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

Full analysis is in
`doc/research/2026-03-12-handle-session-identity-model-research.md`.

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
  Token-object handles remain valid within the logical client instance for as
  long as the underlying object exists, but are still virtual and become invalid
  on context teardown or daemon restart.

### 6. Login State

Login state is scoped to **logical client instance + token**:

- `C_Login` on a session affects the login state of all sessions that the same
  logical client instance holds with that token, matching the PKCS#11 spec's
  per-application semantics.
- `C_Logout` from any session in the logical client instance returns all of that
  instance's sessions with the token to the public state.
- One logical client instance's login has no effect on another logical client
  instance's sessions, even if both are authenticated by the same mTLS
  certificate.

**Backend-authoritative login (D6(3); supersedes ADR-0008).** When another
live logical client already holds the slot login, the shared backend token is
logged in and would answer a second backend `C_Login` with
`CKR_USER_ALREADY_LOGGED_IN` *without* checking the PIN — so the daemon
**cannot** PIN-verify the new login against the token. It therefore returns
the backend's answer faithfully (`CKR_USER_ALREADY_LOGGED_IN`, or
`CKR_USER_ANOTHER_ALREADY_LOGGED_IN` across user types) and mints **no**
logical login: never a login on an unverified PIN, and the presented PIN is
not evaluated at all on this path. At most one logical client holds the login
for a slot at a time; the holder releases it via `C_Logout`, session close,
or context teardown (last-context-out performs a real backend logout, D6(2) /
D9-proxy), after which the next login PIN-verifies against the token
normally. Operators and test harnesses must therefore treat a held slot login
as exclusive and short-lived, and must not share one daemon across tenants
that expect concurrent independent logins on the same token.

**Per-slot login serialization (M5).** The cross-context check for an existing
per-slot login, the backend `C_Login`/`C_Logout`, and the recording of the new
login state are performed under a **per-slot login lock** (`ContextManager::
slot_login_lock`, one `tokio::sync::Mutex` keyed by slot id). Without it, two
logical clients logging into the *same* slot concurrently could both observe
"no other login" and both take the real-login path, issuing two backend
`C_Login` calls for one logical outcome. The lock makes the first client
perform the real `C_Login` while the second blocks, then sees the first
client's state and takes the faithful-`ALREADY` path (D6(3)), so exactly one
backend `C_Login` occurs. The lock is held across the backend call but is
per-slot, so logins on different slots proceed concurrently; the shared token
already serialises same-slot logins internally, so no real concurrency is
lost. Verified by a deterministic concurrency test
(`concurrent_first_login_serializes_to_one_backend_login`) that gates the first
client inside the backend `C_Login` while the second races in.

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
   on last-context-out (D6(2)) -- never disturbing live tenants.
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

- **Default: Shared daemon process.** Multiple logical client instances share
  one loaded backend module within the daemon process. Virtual handle namespaces
  provide caller isolation at the proxy layer. This is correct when the backend
  module properly isolates sessions and handles across concurrent callers.

- **Deferred: Separate backend module instance per logical context.** Another
  `dlopen` handle or `RTLD_LOCAL` does not establish independent native globals,
  including aggregator dependencies. Independent project-managed construction
  is refused before loading under the v0.2 contract. A future shared-domain or
  namespace design would need its own identity/lifecycle proof.

- **Fallback 2: Separate worker process per logical context (or per
  tenant/principal).** For the strongest isolation guarantee, or when the
  backend library is known to be unsafe for in-process multi-tenancy, the daemon
  forks a dedicated worker process for each logical client instance or group of
  instances. This provides a true OS-process isolation boundary when shared
  in-process loading is not trustworthy enough.

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

- **Correct per-application semantics.** The logical client instance model
  preserves PKCS#11's per-application isolation guarantees (`C_CloseAllSessions`,
  per-application login, handle ownership) across the network boundary. An
  implementer can reason about proxy-side state using the same mental model as
  the PKCS#11 spec.

- **Transport resilience.** Transient network interruptions do not destroy
  application state. The lease mechanism provides a window for transparent
  reconnect without requiring the application to re-initialize, re-login, and
  re-open sessions.

- **Multi-tenancy.** Multiple clients -- potentially authenticated by the same
  mTLS certificate -- can safely coexist on one daemon without cross-client
  state leakage. The logical client instance is a natural attachment point for
  future authorization policy, quotas, and audit logging.

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

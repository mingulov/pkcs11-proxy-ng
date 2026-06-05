# ADR-0002: Handle and Session Identity Model

## Status

Proposed

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

**Concurrency note (M5).** The cross-context check for an existing per-slot login
and the recording of a new login state are not performed under a single lock:
they straddle the backend `C_Login` await. Two logical clients logging into the
*same* slot concurrently may therefore both take the real-login path; the shared,
process-wide token serialises them, so the second receives
`CKR_USER_ALREADY_LOGGED_IN` from the backend instead of a synthesised logical
`CKR_OK`. This is a valid PKCS#11 response (two native threads racing `C_Login`
behave the same) and the PIN is still validated (ADR-0008), so the race is
bounded to a transparency nuance under concurrent same-slot login. Making it
exact requires an authoritative per-slot login owner/refcount under one lock;
that is deferred to a focused change with a deterministic concurrency-test
harness rather than an unverifiable inline fix.

### 7. Session Cleanup

`C_CloseAllSessions(slotID)` closes only the sessions opened by the calling
logical client instance for the specified slot. Sessions belonging to other
logical client instances are not affected.

When all sessions a logical client instance holds with a token are closed
(whether individually, via `C_CloseAllSessions`, or via context teardown), that
instance's login state for that token reverts to public.

### 8. Multi-Part Operation State

Active multi-part operation state (sign, verify, encrypt, decrypt, digest,
find) is stored server-side within the logical client instance's session. This
state dies with session close or context expiry. No operation state survives
transport reconnect if the session is lost.

Async operation state (CKR_PENDING results from functions that may return
CKR_PENDING) is stored server-side within the logical client instance's
session, following the same lifecycle rules as multi-part operation state.
Pending operations are polled via C_AsyncComplete. Async operations do NOT
survive C_Finalize or context teardown — they are cancelled along with all
other session state. C_AsyncGetID returns CKR_STATE_UNSAVEABLE because the
proxy does not support persistent async operations in this phase. See
doc/adr/async-persistence-decision.md for the full decision record and
future extension path.

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
   count.
2. **Transport disconnect:** The daemon starts the lease timer. If the client
   reconnects and presents a valid `client_context_id` before expiry, state is
   preserved. If the lease expires, teardown proceeds as in (1).
3. **Daemon restart:** All virtual handles and logical client instances are
   invalidated. No state survives daemon restart.

The proxy does not attempt to redefine PKCS#11's own rule that `C_Finalize` is
undefined if an application calls it while other threads of that same
application are concurrently making Cryptoki calls. The shim preserves that
contract.

### 11. Backend Isolation Fallback Ladder

Not all backend PKCS#11 modules correctly isolate concurrent callers within a
single process. The implementation must support a fallback ladder for backend
isolation:

- **Default: Shared daemon process.** Multiple logical client instances share
  one loaded backend module within the daemon process. Virtual handle namespaces
  provide caller isolation at the proxy layer. This is correct when the backend
  module properly isolates sessions and handles across concurrent callers.

- **Fallback 1: Separate backend module instance per logical context.** If a
  vendor's PKCS#11 library leaks state across callers (e.g., global variables,
  unsafe shared caches), the daemon loads a separate instance of the backend
  module (via `dlopen` with `RTLD_LOCAL` or equivalent) for each logical client
  instance. This may provide process-internal isolation at the cost of higher
  memory usage, but it is **not** treated as a hard isolation guarantee for
  libraries with true process-global state.

- **Fallback 2: Separate worker process per logical context (or per
  tenant/principal).** For the strongest isolation guarantee, or when the
  backend library is known to be unsafe for in-process multi-tenancy, the daemon
  forks a dedicated worker process for each logical client instance or group of
  instances. This provides a true OS-process isolation boundary when shared
  in-process loading is not trustworthy enough.

The correct tier is determined by backend module behavior in practice and
should be configurable per backend. Phase 1 implements the default tier.
Fallback tiers are designed-for but implemented on demand.

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
- **Async persistence not supported.** C_AsyncComplete works (polling for
  CKR_PENDING results). C_AsyncGetID and C_AsyncJoin return spec-compliant
  refusal codes. Full cross-finalize async persistence is deferred.
- **`C_WaitForSlotEvent` deferred.** Hotplug event delivery is not implemented
  in Phase 1.
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
- **`C_WaitForSlotEvent` proxying.** Deferred to Phase 2 or a dedicated ADR on
  slot identity and hotplug behavior.
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
- `C_WaitForSlotEvent` proxying.
- Fallback isolation tiers 1 and 2 (designed-for, not implemented in Phase 1).
- Cross-restart slot identity guarantees and hotplug semantics beyond the
  daemon-lifetime rule defined above.

# ADR-0003: Error Model

## Status

Proposed

## Context

PKCS#11 defines approximately 70 distinct `CKR_*` return values, each carrying
specific semantic meaning. Well-written applications check exact `CK_RV` values
to decide control flow (retry, re-authenticate, abort, etc.). The PKCS#11 spec
itself recommends that applications be generous in interpreting return values,
but the proxy must not introduce ambiguity where the backend was precise.

The Rust PKCS#11 Remote Proxy introduces a gRPC transport layer between the
PKCS#11 backend (loaded by the daemon) and the client shim (loaded by the
application). This creates three distinct error sources:

1. **PKCS#11 backend** -- the real `CK_RV` returned by the underlying module
   for a given operation.
2. **Proxy daemon** -- internal failures in the daemon that are not PKCS#11
   operation results (bugs, resource exhaustion, policy rejections).
3. **gRPC transport** -- network-level failures such as connection loss,
   timeouts, and TLS handshake errors.

A naive design that tunnels everything through gRPC status codes would lose the
exact `CK_RV` value. A design that encodes everything in the protobuf payload
would make transport failures invisible until the client times out. Both
extremes break the contract that PKCS#11 applications rely on.

This ADR also interacts with the handle and session identity model (see
ADR-0002). When a logical client context expires, a handle becomes stale, or
the daemon rejects an unsupported standard operation before it reaches the
backend, the proxy may still be able to produce a valid standard `CK_RV` even
though no backend call was attempted.

## Decision

We adopt a **hybrid error model** with clear separation between PKCS#11
operation results and transport/proxy failures.

### 1. PKCS#11 errors travel in the response payload

Every protobuf response message includes a `ck_rv` field using a fixed-width
64-bit wire representation. This field carries the exact `CK_RV` value returned
by the backend PKCS#11 module, or a proxy-generated standard `CK_RV` when the
proxy can determine the correct PKCS#11 result without consulting the backend.

The client shim extracts this field and returns it directly to the calling
application as the function's `CK_RV` return value, without interpretation or
remapping.

Endpoints validate that the 64-bit wire value fits in the local `CK_RV`
representation before converting it.

When `ck_rv` is `CKR_OK`, the remaining response fields carry the operation
result (output buffer, handle, etc.). When `ck_rv` is any error, the remaining
fields may be absent or zero-valued.

The gRPC status for a successfully-delivered PKCS#11 response is always `OK`,
even if `ck_rv` is an error. A gRPC `OK` status means "the proxy produced a
valid PKCS#11 result and is returning it in `ck_rv`."

### 2. gRPC status codes for failures with no valid PKCS#11 result

gRPC status codes are reserved exclusively for errors that are **not** PKCS#11
operation results. They indicate that the proxy could not produce any valid
standard `CK_RV` for the request, or that the transport itself failed.

| gRPC Status Code     | Meaning in this system                                       |
|----------------------|--------------------------------------------------------------|
| `OK`                 | PKCS#11 call completed; see `ck_rv` in response payload      |
| `UNAVAILABLE`        | Daemon unreachable or connection lost                        |
| `DEADLINE_EXCEEDED`  | Client-set or proxy-set timeout expired before response       |
| `UNAUTHENTICATED`    | mTLS handshake failed or credentials rejected                 |
| `PERMISSION_DENIED`  | Authorization policy rejected the request (not PKCS#11 login) |
| `INVALID_ARGUMENT`   | Malformed protobuf request (missing required fields, etc.)    |
| `FAILED_PRECONDITION`| Daemon is reachable but not in a usable state for the request |
| `RESOURCE_EXHAUSTED` | Daemon at capacity (too many clients, sessions, etc.)         |
| `CANCELLED`          | Request cancelled by client before completion                 |
| `INTERNAL`           | Proxy bug or unexpected daemon crash                          |

Any gRPC status other than `OK` means no valid `ck_rv` is available.

### 3. Client-side mapping for transport failures

When the client shim receives a non-`OK` gRPC status, it must still return a
`CK_RV` to the application. The shim maps gRPC failures to the most
semantically appropriate standard `CK_RV` value.

**Primary mapping table:**

| gRPC Status          | Default CK_RV Mapping               | Notes                                                         |
|----------------------|--------------------------------------|---------------------------------------------------------------|
| `UNAVAILABLE`        | `CKR_DEVICE_ERROR`                   | General: backend unreachable                                  |
| `UNAVAILABLE`        | `CKR_TOKEN_NOT_PRESENT`              | If failure occurs during slot/token enumeration               |
| `DEADLINE_EXCEEDED`  | `CKR_FUNCTION_FAILED`                | Retriable; the operation may not have executed                |
| `UNAUTHENTICATED`    | `CKR_GENERAL_ERROR`                  | PKCS#11 has no transport-auth equivalent                      |
| `PERMISSION_DENIED`  | `CKR_GENERAL_ERROR`                  | Policy rejection is not a PKCS#11 auth failure                |
| `INVALID_ARGUMENT`   | `CKR_ARGUMENTS_BAD`                  | Malformed request from the client library itself              |
| `FAILED_PRECONDITION`| `CKR_GENERAL_ERROR`                  | Reachable daemon, unusable request path                       |
| `RESOURCE_EXHAUSTED` | `CKR_HOST_MEMORY`                    | Daemon cannot accept more work                                |
| `CANCELLED`          | `CKR_FUNCTION_CANCELED`              | Client-initiated cancellation                                 |
| `INTERNAL`           | `CKR_GENERAL_ERROR`                  | Unrecoverable proxy failure                                   |
| Any other status     | `CKR_DEVICE_ERROR`                   | Catch-all for unexpected transport errors                     |

The shim selects among multiple candidate `CK_RV` values based on the PKCS#11
function being called. The function-specific rules are:

- **Functions that do not use a session** (`C_GetSlotList`, `C_GetSlotInfo`,
  `C_GetTokenInfo`, `C_GetMechanismList`, `C_GetMechanismInfo`): transport
  failure maps to `CKR_TOKEN_NOT_PRESENT` or `CKR_DEVICE_ERROR`.
- **Functions that use a session handle**: transport failure maps to
  `CKR_DEVICE_ERROR` (preferred over `CKR_SESSION_HANDLE_INVALID`, because the
  session may still be valid server-side).
- **`C_Initialize`**: transport failure maps to `CKR_DEVICE_ERROR` or
  `CKR_GENERAL_ERROR`.

### 4. Expired and invalid client context handling

When the daemon can determine the correct PKCS#11 meaning of an expired or
invalid client context, it returns `grpc::OK` with the appropriate standard
`ck_rv` value instead of a transport error.

The mapping rules are:

| Function Category                              | CK_RV for expired context            |
|------------------------------------------------|--------------------------------------|
| Any function requiring prior `C_Initialize` but carrying no stale handle | `CKR_CRYPTOKI_NOT_INITIALIZED` |
| Functions using a session handle               | `CKR_SESSION_HANDLE_INVALID`         |
| Functions using an object handle               | `CKR_OBJECT_HANDLE_INVALID`          |
| Functions using a slot that no longer resolves | `CKR_SLOT_ID_INVALID`                |
| `C_Initialize` (re-initialization after expiry)| Succeeds by creating a new context   |

When a function uses both a session handle and an object handle,
`CKR_SESSION_HANDLE_INVALID` takes precedence over `CKR_OBJECT_HANDLE_INVALID`,
consistent with the PKCS#11 spec's error priority rules (section 5.1).

If the client shim has never successfully established a context (e.g.,
`C_Initialize` itself fails due to transport error), the shim returns
`CKR_DEVICE_ERROR` or `CKR_GENERAL_ERROR` from `C_Initialize`. All subsequent
calls return `CKR_CRYPTOKI_NOT_INITIALIZED` without attempting a round-trip.

When a context expires, the client shim should also invalidate its local handle
mapping table so that subsequent calls fail fast without a round-trip.

After a daemon restart, all previously issued `client_context_id` values are
invalid. The next operation receives semantic `ck_rv` values as above, and the
application must call `C_Initialize` again to establish a new context.

`NOT_FOUND` is reserved for native control/resume APIs that do not correspond to
a standard PKCS#11 function.

### 5. No proxy-specific CKR extensions in Phase 1

All proxy-specific error conditions are mapped to existing standard `CK_RV`
values. The proxy does not define its own `CKR_VENDOR_DEFINED`-range values in
Phase 1.

If the standard mapping proves too lossy in practice (e.g., applications cannot
distinguish "daemon unreachable" from "backend hardware error"), proxy-defined
extensions may be introduced in Phase 2 with an opt-in client configuration
flag.

**Backend vendor-defined CKR values** (in the `CKR_VENDOR_DEFINED` range) are a
different matter: if the backend module returns a vendor-defined `CK_RV`, the
proxy passes it through unchanged in the `ck_rv` response field. The proxy does
not interpret, filter, or remap vendor-defined return values from the backend.
This is safe because CKR values are plain integers with no pointer or
serialization hazard.

Note that vendor-defined **mechanisms** are handled separately by ADR-0001: they
are not exposed in `C_GetMechanismList` unless their parameter structures have
been explicitly modeled. The proxy will never attempt an operation with a
vendor-defined mechanism it cannot serialize, so vendor CKR values will only
arise from operations the proxy already knows how to handle.

### 6. Error context metadata for diagnostics

gRPC trailing metadata may carry additional diagnostic information alongside
non-`OK` status codes:

- `x-pkcs11-proxy-ng-error-code` -- a proxy-specific error code string
  for debugging (e.g., `CONTEXT_EXPIRED`, `BACKEND_LOAD_FAILED`)
- `x-pkcs11-proxy-ng-error-detail` -- a human-readable error description

Similarly, when `ck_rv` indicates a backend error, the response message may
include an optional `error_detail` string field with backend-provided context.

**The client shim does NOT expose metadata or detail strings to the PKCS#11
application.** Only the `CK_RV` value is returned through the PKCS#11 function
interface. Diagnostic metadata is available to:

- Client-side structured logging (if enabled)
- CLI and SDK consumers that use the Rust client library directly

### 7. Native client vs. shim behavior

- **Native Rust/gRPC client:** sees non-`OK` gRPC status directly and may expose
  richer typed errors to callers alongside any diagnostic metadata.
- **PKCS#11 shim:** must always collapse non-`OK` gRPC status into a best-effort
  `CK_RV` using the mapping table in section 3.

### 8. Error flow summary

The following table summarizes which error path is used for each error source:

| Error Source           | Carried In            | gRPC Status  | CK_RV Source                      |
|------------------------|-----------------------|--------------|-----------------------------------|
| Backend PKCS#11 result | Response `ck_rv`      | `OK`         | Exact value from backend module   |
| Proxy-generated semantic PKCS#11 result | Response `ck_rv` | `OK` | Standard value chosen by proxy |
| Proxy policy rejection | gRPC status           | `PERMISSION_DENIED` | Shim maps to `CKR_GENERAL_ERROR` |
| Proxy internal bug     | gRPC status           | `INTERNAL`   | Shim maps to `CKR_GENERAL_ERROR` |
| Request validation     | gRPC status           | `INVALID_ARGUMENT`  | Shim maps to `CKR_ARGUMENTS_BAD` |
| Daemon unusable state  | gRPC status           | `FAILED_PRECONDITION` | Shim maps to `CKR_GENERAL_ERROR` |
| Daemon at capacity     | gRPC status           | `RESOURCE_EXHAUSTED` | Shim maps to `CKR_HOST_MEMORY` |
| Client cancellation    | gRPC status           | `CANCELLED`  | Shim maps to `CKR_FUNCTION_CANCELED` |
| Connection lost        | gRPC status           | `UNAVAILABLE`| Shim maps to `CKR_DEVICE_ERROR` |
| Timeout                | gRPC status           | `DEADLINE_EXCEEDED` | Shim maps to `CKR_FUNCTION_FAILED` |
| TLS/auth failure       | gRPC status           | `UNAUTHENTICATED`   | Shim maps to `CKR_GENERAL_ERROR` |

### Design principle

A PKCS#11 application using the client shim should see exactly the same
`CK_RV` values it would see with a local module, except when the transport
itself fails. Transport failures map to the most semantically appropriate
existing `CK_RV` value. If the proxy can determine a correct standard `CK_RV`,
it should return `grpc::OK` plus `ck_rv` rather than forcing the client to infer
one from gRPC status. The application should never receive an error code that
would be impossible from a local PKCS#11 module.

## Decision update (2026-05-30): transport mapping confirmed; reconnect trigger corrected

§5 anticipated that the standard mapping might prove "too lossy" — applications unable
to distinguish "daemon unreachable" from "backend error." We investigated against a
real backend and **confirmed the §3 mapping rather than adding an extension**:

- **kryoptic v1.5.0 uses two result catch-alls** (`src/error.rs`): `CKR_DEVICE_ERROR`
  for the crypto-backend (OpenSSL) path — common for sign/verify/encrypt/digest/wrap
  and integrity failures — and `CKR_GENERAL_ERROR` for internal/plumbing errors
  (serde, ASN.1, IO). So *both* conventional transport values are also routine backend
  results; no standard CK_RV is collision-free.

**Decision: keep §3 unchanged** (session-scoped transport failure → `CKR_DEVICE_ERROR`).
It does not collide with kryoptic's `GENERAL_ERROR` plumbing default; it preserves §3's
rationale that "the session may still be valid server-side, so a retry can resume it";
and because a transport failure must never auto-replay a (non-idempotent) PKCS#11 op,
the value only needs to be *retryable*, not unambiguous. No proxy-defined CKR extension
is introduced — §5 remains a deferred, opt-in Phase-2 option.

**Recovery contract (clarifies §4).** The authoritative, *distinct* "re-`C_Initialize`"
signal after a daemon restart is **`CKR_CRYPTOKI_NOT_INITIALIZED`** — the daemon returns
it for an unknown `client_context_id`. Clients (and test harnesses) should key recovery
on that, **not** on `CKR_DEVICE_ERROR`, which is ambiguous with a backend result.
`CKR_DEVICE_ERROR` means "device/transport problem — retry."

**Reconnect trigger.** The shim marks its cached channel for reconnect
(FOLLOWUP-dns-reresolve) via a **transport-failure hook** fired only when a gRPC
transport `Status` is mapped to a CK_RV (client crate `grpc_status_to_ck_rv[_kind]`) —
**never** by inspecting the returned `ck_rv`. This keeps a backend result (e.g.
kryoptic's `DEVICE_ERROR`/`GENERAL_ERROR` catch-alls) from being mistaken for a
transport failure. (The reconnect flag itself is consumed at `C_Initialize`/interface-
probe time, so this is a correctness/clarity change, not a runtime-performance one.)

## Consequences

### What becomes easier

- **Application compatibility.** Applications that check exact `CK_RV` values
  continue to work correctly. The proxy is transparent for all backend-sourced
  errors.

- **Debugging.** The clean separation between gRPC status and `ck_rv` makes it
  immediately obvious whether a failure is transport-related or
  backend-related. Diagnostic metadata provides further detail without
  polluting the PKCS#11 interface.

- **Implementation clarity.** Daemon developers know that `ck_rv` is the only
  path for PKCS#11 results; client developers know that gRPC status is the
  only path for transport failures. There is no ambiguity about which channel
  to use.

- **Consistency with ADR-0002.** Expired client contexts and stale handles
  produce well-defined semantic `CK_RV` values through the normal response
  path, which aligns with the logical client instance lifecycle.

### What becomes harder

- **Distinguishing proxy failures from backend failures at the application
  level.** An application receiving `CKR_DEVICE_ERROR` cannot tell whether the
  backend hardware failed or the network went down. This is a deliberate
  trade-off: the PKCS#11 interface does not have a "network error" concept, and
  inventing one would break the standard interface contract.

- **Client shim complexity.** The shim must maintain a mapping table indexed by
  function category to select the correct `CK_RV` for each gRPC failure. This
  is modest complexity but must be tested thoroughly.

### What becomes riskier

- **Lossy mapping.** Some transport failures may be misinterpreted by
  applications that treat specific `CK_RV` values as "definitely a hardware
  problem." This risk is accepted in Phase 1 and may be mitigated by
  vendor-defined extensions in Phase 2.

- **Metadata availability.** If diagnostic metadata is lost (e.g., due to a
  proxy between client and daemon that strips headers), debugging becomes
  harder. The metadata channel is best-effort by design.

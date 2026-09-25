# pkcs11-proxy-ng — CK_RV error reference

This document enumerates every `CK_RV` value the proxy stack
(daemon, client, shim) can return to a PKCS#11 application, with
the cause(s), the **operator action** (what someone running the
daemon should do), and the **application action** (what the calling
code should do).

Codes are grouped:

- **Proxy-originated** — the proxy itself decides this, independent
  of what the backend HSM reports.
- **Pass-through** — the proxy faithfully forwards what the
  underlying PKCS#11 backend returned. The proxy does NOT collapse
  these to a generic error (per CLAUDE.md rule 2 and PRD v1.1).

The OASIS PKCS#11 v3.0 spec (`pkcs11t.h`) is the source of truth
for the codes themselves; this reference is about the proxy's
*usage* of each code.

## Proxy-originated

### `CKR_DEVICE_ERROR` (0x30)

**Cause.** Used by the proxy as the canonical "the call could not
reach the backend, or the backend reported a hard failure" code.
Specifically:
- gRPC transport failure (daemon unreachable, TLS handshake fail) on a
  **session-scoped** call. For lifecycle calls the same transport failure maps
  to `CKR_GENERAL_ERROR`, and for slot/token calls to `CKR_TOKEN_NOT_PRESENT`.
- Daemon's `spawn_backend` timeout (`proxy.request_timeout_secs`). Note the
  **client-side** gRPC request timeout (`DeadlineExceeded`) instead maps to
  `CKR_FUNCTION_FAILED` ("the operation may not have executed").
- `classify_backend_outcome` widens this to fold `HOST_MEMORY`,
  `DEVICE_REMOVED`, `TOKEN_NOT_PRESENT` into the health-gate's
  unhealthy set, but the **return value to the caller is still the
  exact backend RV** (per CLAUDE.md rule 2).

**Operator action.** Check `kubectl -n <ns> logs deploy/<daemon>`
for `backend exceeded failure threshold; flipping readiness to
NOT_SERVING`. If present, the daemon has gated itself out of the
Service endpoints. Investigate the backend (HSM) health directly.

**Application action.** Treat as a transient outage. Retry with
exponential backoff. If retries fail repeatedly, surface as an
operator alert.

### `CKR_GENERAL_ERROR` (0x05)

**Cause.** Used by the shim for **lifecycle** RPC failures —
typically when the shim cannot complete the
`C_Initialize`-time backend probe (`GetBackendInterfaces`) because
the daemon is unreachable, returns a malformed response, or the
shim hits a panic that `catch_panics` converts (FFI safety rule).

**Operator action.** Verify the daemon is reachable at the URL
configured by `PKCS11_PROXY_ENDPOINT` and that mTLS files (if any)
are readable by the shim's user. Inspect daemon logs for crashes
during `GetBackendInterfaces`.

**Application action.** Same as `CKR_DEVICE_ERROR`. Some
applications retry `C_Initialize` on `CKR_GENERAL_ERROR`; that's
safe with this proxy.

### `CKR_CRYPTOKI_NOT_INITIALIZED` (0x190)

**Cause.** The application called a session/object/operation
function without first successfully calling `C_Initialize`, or
between `C_Finalize` and the next `C_Initialize`.

**Operator action.** Usually no operator action; this is an
application-layer bug. If you see it from a previously-working
application, check whether the shim was reloaded mid-flight (e.g.
a deployment that swapped the `.so` while the process was running).

**Application action.** Call `C_Initialize` and retry.

### `CKR_CRYPTOKI_ALREADY_INITIALIZED` (0x191)

**Cause.** `C_Initialize` called a second time without an
intervening `C_Finalize`.

**Operator action.** None — application logic bug.

**Application action.** Treat as success if you only need
initialization to "happen at least once"; otherwise call
`C_Finalize` first.

### `CKR_ARGUMENTS_BAD` (0x07)

**Cause.** A null pointer in a required slot, a struct size
mismatch, or an out-of-range argument the shim caught before
forwarding to the daemon.

**Operator action.** None — application-layer issue.

**Application action.** Audit the call site against the PKCS#11
v3.0 spec for the specific function.

### `CKR_BUFFER_TOO_SMALL` (0x150)

**Cause.** The application's output buffer is smaller than the
backend reports as required. The proxy uses **exact-output
semantics** (CLAUDE.md rule 2): the daemon forwards the caller's
exact buffer spec to the backend, and the backend's
`CKR_BUFFER_TOO_SMALL` is propagated verbatim.

**Operator action.** None.

**Application action.** Follow the PKCS#11 two-call convention:
call once with `pBuffer = NULL_PTR` to get the required size,
allocate, then call again with the right-sized buffer.

### `CKR_SLOT_ID_INVALID` (0x03)

**Cause.** The slot ID supplied by the application isn't in the
daemon's slot map. Typically because the slot was removed between
`C_GetSlotList` and the current call, or the application is reusing
a stale slot ID across `C_Initialize` cycles.

**Operator action.** None unless slot churn is unexpected.

**Application action.** Refresh slot list via `C_GetSlotList`.

### `CKR_SESSION_HANDLE_INVALID` (0xB3)

**Cause.** The session handle the application supplied doesn't
exist in the daemon's session map, has expired (lease-based
eviction in `context_manager`), or was opened by a different
process and the daemon lost the binding (daemon restart).

**Operator action.** If you see a burst of these after a
restart/rollout, the symptom is expected — applications should
re-open sessions on the next call. If they persist, check the
daemon's eviction-task log for the lease duration in use.

**Application action.** Call `C_OpenSession` and retry.

### `CKR_OBJECT_HANDLE_INVALID` (0x82)

**Cause.** Same shape as `CKR_SESSION_HANDLE_INVALID` but for
object handles. The proxy maintains per-session object handles and
evicts them when the session closes
(`evict_session_caches`).

**Operator action.** None unless a regression in cache eviction is
suspected; check daemon logs for `evict_session_caches` traces.

**Application action.** Re-query objects via `C_FindObjects*`.

### `CKR_MECHANISM_INVALID` (0x70)

**Cause.** The shim's mechanism registry doesn't recognise the
mechanism the application requested. Either the registry hasn't
been loaded yet (rare; `C_Initialize` race window), the registry
is out-of-date relative to the backend, or the mechanism is
genuinely unsupported by this backend.

**Operator action.** Check the daemon's `mechanism registry ready`
log line for the loaded revision. Reload via `kill -HUP <pid>`
after editing `mechanism_params.toml`. If a vendor mechanism is
missing, layer it via `[mechanisms].config_path` (see runbook §5).

**Application action.** Call `C_GetMechanismList` to enumerate
what's actually available.

### `CKR_MECHANISM_PARAM_INVALID` (0x71)

**Cause.** The shim received a mechanism parameter shape that
doesn't match what its registry says the mechanism takes. **Most
common case:** a vendor mechanism is in the registry under a shape
that doesn't match what the backend wants. **Less common:** a
genuine application bug.

**Operator action.** Verify the mechanism's row in the registry
TOML against the backend's vendor docs. The proxy intentionally
returns `CKR_MECHANISM_PARAM_INVALID` rather than guessing
(CLAUDE.md rule 12).

**Application action.** Audit the `CK_MECHANISM` struct against
the spec / vendor docs.

### `CKR_FUNCTION_NOT_SUPPORTED` (0x54)

**Cause.** The shim called a function that the backend's
`CK_FUNCTION_LIST` reports as null. The proxy never fabricates an
implementation.

**Operator action.** Confirm the backend version supports the
function; some HSMs ship truncated function lists for older
PKCS#11 versions.

**Application action.** Use an alternative function or fall back
to a different mechanism.

## Pass-through (proxy forwards backend's exact value)

These are returned verbatim by the backend; the proxy does not
originate, transform, or collapse them. See OASIS PKCS#11 v3.0
§5.1 for the canonical meaning. The proxy's role is just to
preserve the value across the gRPC hop.

| CK_RV | Hex | Typical cause |
| --- | --- | --- |
| `CKR_HOST_MEMORY` | 0x02 | Backend exhausted heap. **Also folded into the daemon's backend-health gate** alongside DEVICE_ERROR. |
| `CKR_DEVICE_MEMORY` | 0x31 | HSM ran out of internal storage. |
| `CKR_DEVICE_REMOVED` | 0x32 | HSM yanked. Folded into health gate. |
| `CKR_TOKEN_NOT_PRESENT` | 0xE0 | Token not in slot. Folded into health gate. |
| `CKR_FUNCTION_FAILED` | 0x06 | Backend's catch-all for non-specific failures. **Operator action:** check daemon log for the corresponding `backend call returned RV=…` line for the underlying cause; some backends bury more specific codes in their own logs. |
| `CKR_FUNCTION_CANCELED` | 0x50 | Backend cancelled a long-running op. |
| `CKR_FUNCTION_NOT_PARALLEL` | 0x51 | Backend rejects concurrent ops on a single session. |
| `CKR_PIN_INCORRECT` | 0xA0 | Wrong PIN at `C_Login`. The proxy **never** logs the PIN itself (CLAUDE.md rule 4); only the RV is logged. |
| `CKR_USER_NOT_LOGGED_IN` | 0x101 | Operation requires a prior `C_Login`. |
| `CKR_USER_ALREADY_LOGGED_IN` | 0x100 | Second `C_Login` on a session with a still-active login. |
| `CKR_USER_TYPE_INVALID` | 0x103 | `CKU_USER` vs `CKU_SO` mismatch. |
| `CKR_OPERATION_ACTIVE` | 0x90 | Tried to start a new op while one is mid-stream (e.g. second `C_SignInit` before `C_SignFinal`). |
| `CKR_OPERATION_NOT_INITIALIZED` | 0x91 | `C_Sign` called without preceding `C_SignInit`. |
| `CKR_SAVED_STATE_INVALID` | 0x160 | `C_SetOperationState` rejected the blob. |
| `CKR_STATE_UNSAVEABLE` | 0x180 | `C_GetOperationState` on a non-saveable op. |
| `CKR_SESSION_COUNT` | 0xB1 | Token's session limit hit. |
| `CKR_SIGNATURE_INVALID` | 0xC0 | Bad signature at `C_Verify`. |
| `CKR_DATA_INVALID` | 0x20 | Bad input format. |
| `CKR_DATA_LEN_RANGE` | 0x21 | Input length outside mechanism's permitted range. |
| `CKR_TEMPLATE_INCONSISTENT` | 0xD1 | Object create/set template invalid. |
| `CKR_ATTRIBUTE_SENSITIVE` | 0x11 | `C_GetAttributeValue` on a sensitive attribute. |
| `CKR_ATTRIBUTE_TYPE_INVALID` | 0x12 | Unknown attribute type. |
| `CKR_NO_EVENT` | 0x08 | `C_WaitForSlotEvent` in non-blocking mode with nothing pending. |

For each of these the **operator action** is: check the daemon's
`backend call returned RV=…` line to confirm the value came from
the backend and not from a transport layer; if it did, the issue
is in the backend (HSM driver, PIN policy, mechanism availability)
or the application.

## Quick triage flow

1. **Application reports any CK_RV** → check the daemon's structured
   log at the matching request_id (the request-scoped trace-id
   middleware emits `request_id` in every span).
2. The log line `backend call returned RV=0x<hex>` proves the RV
   came from the backend, not from transport. If absent, the
   proxy's transport/timeout layer originated it (see proxy-
   originated section above).
3. If the same RV is repeated and folded into the unhealthy set
   (HOST_MEMORY / DEVICE_REMOVED / TOKEN_NOT_PRESENT / DEVICE_ERROR),
   watch for `backend exceeded failure threshold; flipping
   readiness to NOT_SERVING`. The pod will be pulled from the
   Service after `backend_health_consecutive_failures` consecutive
   failures.

## Daemon startup failures (not CK_RV)

These surface as process-startup errors before any PKCS#11 call is served:

| Message fragment | Meaning | Operator action |
|---|---|---|
| `already reserved (epoch N)` | A second backend provider chain was registered in this process | Run one provider chain per daemon process (see `doc/release/native-mechanism-ownership.md`, "One provider chain per embedding process") |
| `constructor registry poisoned` / `constructor registry lock poisoned` | A constructor panicked during registration, or the registry mutex was poisoned | Restart the daemon; if it recurs, inspect the panic backtrace and fix the backend module |
| `native FFI unavailable on this platform` | A native constructor was used off supported Linux targets | Run the daemon on Linux GNU/musl x86_64 or x86, or use a portable/mock constructor |
| `constructor epoch exhausted` | Internal epoch counter overflow (defensive; not expected in service) | Restart the daemon and report the incident |

## Related docs

- Runbook §6 (Troubleshooting common CK_RV codes) — surfaces the
  three highest-frequency codes with concrete `kubectl` commands.
- `doc/audit/r3-spec-conformance.md` — proves the shim returns
  spec-compliant CK_RV under transport/lifecycle failures.
- `doc/audit/r8-chaos.md` scenario 2 — end-to-end proof that
  persistent `HOST_MEMORY` flips the health gate.

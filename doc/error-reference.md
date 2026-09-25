# pkcs11-proxy-ng — CK_RV error reference

This reference explains common return values from the shim and daemon,
including who produced them and what to do next. The same value can come
from the proxy or the provider; use the request ID in daemon logs to tell.
See the PKCS#11 specification for the complete meaning of each code.

## Proxy-originated

### `CKR_DEVICE_ERROR` (0x30)

**Cause.** The proxy uses this for these failures:
- gRPC transport failure (daemon unreachable, TLS handshake fail) on a
  **session-scoped** call. For lifecycle calls the same transport failure maps
  to `CKR_GENERAL_ERROR`, and for slot/token calls to `CKR_TOKEN_NOT_PRESENT`.
- Exact-output contract violation: the provider or daemon response has
  effects that cannot be safely returned to the caller. On message calls,
  the shim clears local operation state because the outcome is uncertain.

The provider can also return `CKR_DEVICE_ERROR`, which the proxy forwards
unchanged. A provider-returned `CKR_DEVICE_ERROR` alone does not mark the
daemon unhealthy; repeated backend timeouts or selected provider errors can.

Timeouts, circuit-breaker trips, login-lock contention, and PIN cooldown have
the distinct return values described below.

**Operator action.** Check `kubectl -n <ns> logs deploy/<daemon>`
for `backend exceeded failure threshold; flipping readiness to
NOT_SERVING`. If present, the daemon has gated itself out of the
Service endpoints. Investigate the backend (HSM) health directly.

**Application action.** Check whether the call may have reached the provider
before retrying a state-changing operation. Back off on transport failures;
alert an operator if errors persist.

### `CKR_GENERAL_ERROR` (0x05)

**Cause.** Used by the shim for **lifecycle** RPC failures —
typically when the shim cannot complete the
`C_Initialize`-time backend probe (`GetBackendInterfaces`) because
the daemon is unreachable, returns a malformed response, or the
shim hits a panic that `catch_panics` converts (FFI safety rule).
Also originated by the proxy for:
- Per-slot login-lock contention: another operation holds the
  slot's login serialization lock past the configured bound. The
  backend was untouched; retry.
- Daemon wrong-length response to `C_GenerateRandom`: the
  daemon returned a byte count differing from the requested length.
  A protocol violation, failed closed before any caller memory is
  written.
- 64-bit daemon `ck_rv` unrepresentable in the host `CK_RV`:
  on hosts where `CK_ULONG` is 32 bits (ILP32, Windows LLP64) a peer
  RV above `u32::MAX` saturates here with a shim-side warn. No
  genuine backend emits such values; saturation indicates a
  hostile or buggy peer.

**Operator action.** Verify the daemon is reachable at the URL
configured by `PKCS11_PROXY_ENDPOINT` and that mTLS files (if any)
are readable by the shim's user. Inspect daemon logs for crashes
during `GetBackendInterfaces`. For login-lock refusals, look for a
slow or wedged backend login pinning the slot. For wrong-length
random, the daemon or backend is misbehaving — investigate the
provider and file a bug.

**Application action.** Retry `C_Initialize` after the connection is
restored. For other operations, reconcile state before retrying if the
call may have run.

### `CKR_FUNCTION_FAILED` (0x06)

**Cause.** The daemon's `spawn_backend` call exceeded
`proxy.request_timeout_secs`.
Outcome-ambiguous: the backend call keeps running and may still
complete — the same meaning as the **client-side** gRPC request
timeout (`DeadlineExceeded`), which already mapped to this code.

**Operator action.** Check whether the backend (HSM) is slow or
wedged: look for `Backend call timed out` lines and a rising
`stuck_calls` count. Consider raising
`proxy.request_timeout_secs` or investigating HSM responsiveness.

**Application action.** The call may still finish at the provider. Reconcile
state before retrying a non-idempotent operation.

### `CKR_HOST_MEMORY` (0x02)

**Cause.** The daemon's circuit breaker rejected the call because its global
or per-connection budget was exhausted. The backend was not called.

**Operator action.** Look for `Backend circuit breaker tripped` and compare
call load with `proxy.max_concurrent_backend_calls` and provider capacity.

**Application action.** Back off and retry. If it persists, the
daemon is saturated — surface as an operator alert.

### `CKR_PIN_LOCKED` (0xA4)

**Cause.** The daemon fast-rejected a `C_Login`/`C_LoginUser` because
the slot's aggregate failed-login budget tripped and the cooldown
window is active. The proxy
stops feeding the backend's shared PIN-lockout counter. The app must
stop trying PINs — the same action a backend lockout demands.

**Operator action.** None unless unexpected: repeated trips mean a
client is guessing PINs. Check audit logs for the failing identity.

**Application action.** Do not retry the PIN until the cooldown
expires; tell the user the PIN is temporarily refused.

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

**Application action.** Avoid a second `C_Initialize` until the matching
`C_Finalize` has completed.

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
semantics**: the daemon forwards the caller's
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

**Cause.** The object handle is unknown, no longer valid in the current
context, unavailable under the client's object policy, or rejected by the
provider. A destroyed object or a session object
whose session closed can produce this value. Token objects may persist even
when their old handles cannot be reused after a daemon restart.

**Operator action.** After a restart, check that the expected token object is
visible to the provider. Investigate repeated failures without a restart.

**Application action.** Reopen the session if needed and find the object again
with `C_FindObjects*` before using its new handle.

### `CKR_MECHANISM_INVALID` (0x70)

**Cause.** The registry excludes the mechanism, the client's authorization
policy denies it, or the provider returned this value. An unknown mechanism
with no parameters is not rejected merely because it is absent from the
registry; the provider still decides whether to support it.

**Operator action.** Check the client's mechanism grants, the registry's
`exclude` list, and the daemon's `mechanism registry ready` revision. If an
exclusion needs changing, edit the file selected by `[mechanisms].config_path`
and reload it as described in the
[runbook](runbooks/operating-pkcs11-proxy-ng.md#5-updating-mechanism-registry-vendor-extensions-eg-cloudhsm).
If the provider returned the value, check its mechanism list and policy.

**Application action.** Call `C_GetMechanismList` to enumerate
what's actually available.

### `CKR_MECHANISM_PARAM_INVALID` (0x71)

**Cause.** The shim cannot parse a parameter shape under its registry, or
the provider returned this value for parameters it rejects. Unknown
mechanisms with parameters need a modeled shape to cross the proxy.

**Operator action.** Compare the registry entry with the provider's
documented parameter shape and check whether the provider returned the error.

**Application action.** Audit the `CK_MECHANISM` struct against
the spec / vendor docs.

### `CKR_FUNCTION_NOT_SUPPORTED` (0x54)

**Cause.** The provider's `CK_FUNCTION_LIST` has no entry for the requested
function. The proxy also returns this for a discovery or session-info
response with no required `info` payload.
In v0.2, a blocking `C_WaitForSlotEvent` is refused locally with this value;
use `CKF_DONT_BLOCK` for that call.
Also returned at `C_Initialize` when the shim's and daemon's
exact-output effects version ranges are disjoint: the
peers cannot agree on an effects encoding, so init fails fast
instead of corrupting per-RPC effects later.

**Operator action.** Check provider support for the function. For a
`C_Initialize` failure, compare shim and daemon versions and upgrade the
older peer if their exact-output protocol ranges do not overlap.

**Application action.** Use an alternative function or fall back
to a different mechanism.

## Pass-through (proxy forwards backend's exact value)

When the provider returns these values, the proxy forwards them unchanged.
Some values can also originate in the proxy, as noted in the table. Match the
request ID to daemon logs to identify the source.

| CK_RV | Hex | Typical cause |
| --- | --- | --- |
| `CKR_HOST_MEMORY` | 0x02 | Backend exhausted heap. **Also folded into the daemon's backend-health gate** (a backend-returned `DEVICE_ERROR`, by contrast, is a per-request response and does not flip readiness). **Also originated by the proxy** for circuit-breaker trips (see proxy-originated section). |
| `CKR_DEVICE_MEMORY` | 0x31 | HSM ran out of internal storage. |
| `CKR_DEVICE_REMOVED` | 0x32 | HSM yanked. Folded into health gate. |
| `CKR_TOKEN_NOT_PRESENT` | 0xE0 | Token not in slot. Not folded into the health gate (per-request response). |
| `CKR_FUNCTION_FAILED` | 0x06 | Backend's catch-all for non-specific failures. **Operator action:** run the daemon with debug logging (`RUST_LOG=pkcs11_proxy_ng=debug`) and check for the corresponding per-call `backend outcome classified` line for the underlying cause; some backends bury more specific codes in their own logs. **Also originated by the proxy** for backend-call timeouts (see proxy-originated section). |
| `CKR_FUNCTION_CANCELED` | 0x50 | Backend cancelled a long-running op. |
| `CKR_FUNCTION_NOT_PARALLEL` | 0x51 | Legacy parallel-operation status, commonly returned by `C_GetFunctionStatus` or `C_CancelFunction` when no legacy parallel operation is available. |
| `CKR_PIN_INCORRECT` | 0xA0 | Wrong PIN at `C_Login`. The proxy **never** logs the PIN itself; only the RV is logged. |
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
| `CKR_DATA_LEN_RANGE` | 0x21 | Input length outside mechanism's permitted range. **Also originated by the shim** when a 64-bit count/length argument (e.g. `C_FindObjects` `ulMaxObjectCount`) exceeds the u32 wire width. |
| `CKR_TEMPLATE_INCONSISTENT` | 0xD1 | Object create/set template invalid. |
| `CKR_ATTRIBUTE_SENSITIVE` | 0x11 | `C_GetAttributeValue` on a sensitive attribute. |
| `CKR_ATTRIBUTE_TYPE_INVALID` | 0x12 | Unknown attribute type. |
| `CKR_NO_EVENT` | 0x08 | `C_WaitForSlotEvent` in non-blocking mode with nothing pending. |

For provider errors, compare the application's request ID with the daemon's
`backend outcome classified` debug log. Enable
`RUST_LOG=pkcs11_proxy_ng=debug` when needed. A provider-returned error calls
for provider or application triage; a proxy-originated error calls for the
specific action above. Avoid logging PINs or request payloads.

## Quick triage flow

1. Match the application's request ID with the daemon's structured log.
2. If the debug log says `backend outcome classified`, the provider returned
   the value. Enable `RUST_LOG=pkcs11_proxy_ng=debug` before relying on the
   absence of that line; other missing logs need investigation.
3. If readiness becomes `NOT_SERVING`, look for
   `backend exceeded failure threshold` and investigate provider health and
   backend timeouts.

## Daemon startup failures (not CK_RV)

These surface as process-startup errors before any PKCS#11 call is served:

| Message fragment | Meaning | Operator action |
|---|---|---|
| `already reserved (epoch N)` | A second backend provider chain was registered in this process | Run one provider chain per daemon process; see the [native ownership contract](release/native-mechanism-ownership.md) |
| `constructor registry poisoned` / `constructor registry lock poisoned` | A constructor panicked during registration, or the registry mutex was poisoned | Restart the daemon; if it recurs, inspect the panic backtrace and fix the backend module |
| `native FFI unavailable on this platform` | A native constructor was used on an unqualified target | Use a target admitted by the [native ownership contract](release/native-mechanism-ownership.md), or use a portable/mock constructor |
| `constructor epoch exhausted` | Internal epoch counter overflow (defensive; not expected in service) | Restart the daemon and report the incident |

## Related docs

- [Runbook §6](runbooks/operating-pkcs11-proxy-ng.md#6-troubleshooting-common-ck_rv-codes) — common errors and operator checks.
- [Transport-error mapping](../crates/client/src/error.rs) — implementation and
  unit tests for transport/lifecycle return codes.

# ADR-0008: Cross-client logical-login PIN verifier

**Status:** Accepted (2026-06-04)
**Relates to:** ADR-0002 §6 (logical client login), ADR-0007 / A2 (backend process isolation)

## Context

Many logical clients share one backend (the daemon is a single PKCS#11
application). PKCS#11 token login is **process-wide**: once one client logs the
backend token in, a second client's `C_Login` returns
`CKR_USER_ALREADY_LOGGED_IN` from the backend **without validating that client's
PIN**.

To preserve per-client login independence (ADR-0002 §6: "a fresh logical client
should not inherit the backend's already-logged-in state"), the daemon
*synthesized* a logical login: when another context already held the same login
state for the slot, it returned `CKR_OK` and recorded the state — **without
reading the presented PIN.** A client could therefore `C_Login` with a wrong or
empty PIN and receive `CKR_OK` (the 2026-06-04 review's A1 finding).

Two distinct problems were entangled here:

1. **Login-response transparency / correctness:** the proxy returned `CKR_OK`
   for an unvalidated/incorrect PIN, which a native module never does.
2. **Actual access control:** because the backend token login is process-wide
   and the proxy does **not** gate crypto operations on its own `login_state`,
   a co-located client already has effective crypto access regardless of the
   proxy's login response. Closing *this* requires per-client backend isolation
   (A2 / ADR-0007), which is deferred.

## Decision

Fix problem (1) now; document that problem (2) is bounded by the shared-backend
architecture and is the domain of A2.

The daemon keeps a **per-`(slot, login state)` PIN verifier** — a salted
SHA-256 hash (random per-process salt; the raw PIN is never stored) captured at
the first *successful* backend login. On a subsequent logical login for the
same `(slot, state)`, the presented PIN is hashed and compared:

- match → synthesize `CKR_OK` and record the logical login (feature preserved);
- mismatch → `CKR_PIN_INCORRECT` (the bypass is closed);
- no verifier recorded (e.g. the original login used the protected-auth path) →
  fall through to a real backend `C_Login` rather than synthesize an
  unvalidated `OK`.

The verifier is dropped when the last holder performs a real `C_Logout` (the
shared token is then logged out; a fresh login re-captures it).

## Alternatives considered

- **(a) Backend-authoritative login** — drop the synthesized `OK` and surface
  the backend's real CK_RV. Rejected: a fresh client with the *correct* PIN
  would get `CKR_USER_ALREADY_LOGGED_IN` instead of `OK` (also non-transparent),
  and it removes the deliberately-designed ADR-0002 §6 independence.
- **(c) Defer entirely to A2** — leaves the `CKR_OK`-for-wrong-PIN transparency
  defect in place. Rejected.

## Consequences

- The login *response* is now correct: wrong PIN → `PIN_INCORRECT`, correct PIN
  → `OK`, independence preserved. Verified by
  `cross_client_login_with_wrong_pin_is_rejected` plus the existing
  logical-login state-machine tests.
- A salted PIN-hash now lives in daemon memory for the duration of a token
  login. Given that an attacker with daemon memory already holds the live,
  logged-in backend session, this does not materially widen exposure; the salt
  guards against rainbow-table recovery of the PIN value for reuse elsewhere.
- The verifier is refreshed on `C_SetPIN` (the new PIN is re-hashed for the
  slot's current login state), so a logical login with the new PIN is accepted
  immediately. `C_InitPIN` needs no refresh: it requires an SO session, and a
  token cannot be SO- and User-logged-in at once, so no concurrent User
  verifier can exist for that slot to go stale.
- **Out of scope:** true per-client access isolation (a co-located client doing
  crypto without its own valid login) requires backend-per-client isolation
  (A2 / ADR-0007). This ADR fixes the login-response contract only.

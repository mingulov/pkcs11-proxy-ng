# ADR-0010: Transparent Forwarding By Default

## Status
**Accepted (2026-06-11).** Scope 1 (NULL-mechanism init forwarding) implemented
with this ADR. Scope 2 (NULL data-pointer wire fidelity, transport-limit RV
finalization, `sanitize_inputs` option) implemented 2026-06-12.

## Context

A full proxied-vs-direct `pkcs11-check` matrix run (2026-06-11) exposed places
where the proxy substituted its own judgment for the backend module's:

- The shim mapped `C_VerifyInit`/`C_DigestInit` with a NULL `pMechanism` to the
  PKCS#11 3.0 `C_SessionCancel`. Modules without that function returned
  `CKR_FUNCTION_NOT_SUPPORTED` (softhsm2) and modules with it returned `CKR_OK`
  (kryoptic) — while the same modules loaded directly return their own answers
  (`CKR_ARGUMENTS_BAD`, `CKR_MECHANISM_INVALID`, or a native digest cancel).
  The five sibling init paths (sign, sign-recover, verify-recover, encrypt,
  decrypt) already forwarded `C_*Init(NULL)` verbatim and showed no divergence.
- The shim's input reader flattens `(NULL pointer, length > 0)` into an empty
  byte slice, so strict modules (softhsm2, opencryptoki) that natively reject
  the call with `CKR_ARGUMENTS_BAD` instead see valid empty input and return
  `CKR_OK`.

PKCS#11 providers genuinely differ on edge inputs. Any return value the proxy
synthesizes — including a "spec-correct" `CKR_ARGUMENTS_BAD` — is wrong for
some provider, and per-call translation policy accretes without bound. This
conflicts with the primary correctness requirement (Contributor Rules §2): an
application must not be able to distinguish the shim from the real module.

The hard case is a module that crashes on such input: NSS softokn dereferences
a NULL `pMechanism` in `C_DigestInit` and SEGVs. Loaded directly, that crash
kills the calling application. Proxied, it kills the shared daemon — including
other clients' sessions.

## Decision

1. **The proxy is a transport, not a policy layer.** The shim serializes call
   parameters with full fidelity — a NULL pointer is represented as NULL on the
   wire (NULL-mechanism init already travels as `mechanism: None` on the
   existing Init RPCs), never coerced to an empty or default value — and the
   daemon reconstructs the exact call against the backend module. The module's
   native `CK_RV` is returned untranslated. This applies in both directions,
   including error values.
2. **All seven `ffi_*_init_cancel` paths forward the original `C_*Init(NULL)`**
   to the module. The `C_SessionCancel` mapping for verify/digest is removed.
   A source-level quality gate (`local_quality_gate_test.rs::
   ffi_init_cancel_paths_forward_null_mechanism_init_verbatim`) guards this.
3. **A module crash on forwarded input is accepted default behavior.** It is
   the module's direct-load behavior; the daemon supervisor restarts, and other
   clients of the shared daemon observe a transport-failure `CK_RV` per the
   error-mapping contract (ADR-0003) and reconnect. Structural blast-radius
   reduction remains the multi-daemon partitioning strategy of ADR-0007 — not
   per-call smartness.
4. **Input sanitization is a separate, daemon-side, default-off option**
   (`sanitize_inputs`, planned with Scope 2). When enabled by the operator, the
   daemon rejects spec-invalid inputs (NULL mechanism on init, NULL data
   pointer with non-zero length, lengths beyond the `isize` boundary) with
   `CKR_ARGUMENTS_BAD` before they reach the module. Daemon-side because that
   is the trust boundary the operator controls; a shim-side option would not
   protect the daemon from non-cooperating clients. Enabling it deliberately
   trades transparency for availability.

## Limits — transport-impossible inputs

Faithful forwarding requires materializing the client's buffer to cross the
wire; where that is physically impossible, a synthesized return value is
forced and is documented here as an acknowledged transparency limit, NOT an
exception that licenses other synthesis:

- **(a) Unreadable data lengths:** valid pointer with `len` whose byte size
  overflows or exceeds `MAX_SERIALIZABLE_BYTES` (512 MiB). The shim returns
  `CKR_ARGUMENTS_BAD` (stable; was: `CKR_GENERAL_ERROR` via panic guard before
  Scope 2). Direct modules return their own provider-specific RVs without
  reading the buffer, so this is a known, tested divergence.
- **(b) Unmaterializable embedded mechanism-parameter payloads:** absurd
  lengths on embedded data fields inside mechanism-parameter structs (e.g.
  GCM/CCM AAD, PBE salt, IKE/KEA public data, GOST IV/UKM, derived-key
  nonce/tag). The shim falls back to the raw-param-struct path; the daemon
  rejects Raw with `CKR_MECHANISM_PARAM_INVALID` at the FFI reconstruction
  boundary (not shim-synthesized). This is the same chain as the pre-existing
  NULL-embedded-pointer treatment.
- **(c) Message-API parameter embedded fields (class 5):** oversized lengths
  are flattened to empty (pre-existing behavior, unchanged). Deferred to the
  class-5 follow-up plan.
- The constant `MAX_MECHANISM_PARAM_STRUCT_LEN` (64 KiB, renamed from
  `MAX_MECHANISM_PARAM_LEN`) bounds only parameter-STRUCT lengths; embedded
  data fields are bounded by `MAX_SERIALIZABLE_BYTES` (512 MiB). Legitimate
  AAD/seed/label/IV values larger than 64 KiB no longer hit the struct cap.

## Limits — NULL output-length pointer (out of scope, follow-up needed)

Calls where the *output-length* pointer (`pulLen`) is NULL (e.g.
`C_Encrypt(out=NULL, pulLen=NULL)`) are explicitly out of scope for Scope 2.
These already have defined spec semantics via the exact-output RPCs
(`ByteOutputExact`, etc.) and are handled separately from data-input pointers.
The `-length` variant test family (`test_null_argument_rejection_terminates_*`
with NULL `pulLen`) reveals a known divergence: the shim synthesizes
`CKR_ARGUMENTS_BAD` locally before the backend op is attempted, while direct
modules reject AND terminate the active operation. This is tracked as a
follow-up (output-spec NULL fidelity) and does not affect the Scope 2
correctness claims.

## Consequences

- Proxied NULL-mechanism init behavior now matches each module's direct
  behavior: softhsm2 returns `CKR_ARGUMENTS_BAD`, NSS verify returns
  `CKR_MECHANISM_INVALID`, modules with native digest-cancel semantics keep
  them.
- NSS `C_DigestInit(NULL)` crashes the daemon by default. Test harnesses run
  with supervisor restart (`PROXY_FAIL_FAST_ON_DAEMON_CRASH=0`); production
  deployments that cannot tolerate this enable `sanitize_inputs`, or rely on
  multi-daemon partitioning (ADR-0007).
- Scope 2 (implemented 2026-06-12): NULL data-input pointers travel verbatim
  shim → wire → daemon → backend FFI via the additive `*_null_len` proto
  fields. The module's native `CK_RV` and its operation-termination semantics
  (if any) reach the client unchanged. This covers class-1 byte-data inputs
  (encrypt/decrypt/sign/verify/digest, combined ops, wrap/unwrap, KEM,
  set-operation-state, message-API data). PIN inputs (class 2), attribute
  templates (class 3), and embedded mechanism/message-param pointers (classes
  4–5) are deferred to follow-up plans; their current behavior is unchanged.
- `sanitize_inputs` (Scope 2, daemon config, default OFF): rejects NULL
  data pointers with `len > 0` and NULL mechanism on init with
  `CKR_ARGUMENTS_BAD` before the module is called. Known divergence: a
  sanitize-mode reject does NOT terminate the active backend operation the
  way a module-returned error would; applications relying on operation
  termination from a rejected call must not depend on `sanitize_inputs` for
  that behavior. This is an accepted trade-off (availability over full
  fidelity) documented here rather than silently fixed.
- Known bypass: the 8 LEGACY per-operation RPC fields
  (`EncryptRequest`/`DecryptRequest`/`DigestRequest`/`SignRequest` singles and
  the 4 combined-update requests) do not carry `*_null_len` semantics and are
  not `sanitize_inputs`-gated. A hand-crafted non-shim gRPC client using those
  legacy paths bypasses both the NULL-wire-fidelity and the sanitize gate. The
  shim routes exclusively through `ByteOutputExact`; this bypass is not
  reachable through normal shim use.
- Future "compatibility" fixes that would synthesize or translate a `CK_RV` on
  the default path are rejected by policy; they belong behind `sanitize_inputs`
  or in the backend module itself.

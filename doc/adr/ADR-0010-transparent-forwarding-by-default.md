# ADR-0010: Transparent Forwarding By Default

## Status
**Accepted (2026-06-11).** Scope 1 (NULL-mechanism init forwarding) implemented
with this ADR; Scope 2 (NULL data-pointer wire fidelity + daemon-side
`sanitize_inputs` option) is a planned follow-up.

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

- Lengths whose byte size overflows or exceeds the serialization cap
  (`MAX_SERIALIZABLE_BYTES`, currently 512 MiB) cannot be forwarded. The shim
  returns one documented, stable RV for this class (today `CKR_GENERAL_ERROR`
  via the panic guard; the Scope 2 plan will finalize the value and tests).
  Direct modules return their own provider-specific RVs without reading the
  buffer, so this class is a known, tested divergence.
- Caps on mechanism/message parameter payloads (`MAX_MECHANISM_PARAM_LEN`)
  must be large enough that only unmaterializable inputs hit them — a cap
  that rejects legitimate inputs (e.g. valid AAD sizes) is a bug, not a
  limit.

## Consequences

- Proxied NULL-mechanism init behavior now matches each module's direct
  behavior: softhsm2 returns `CKR_ARGUMENTS_BAD`, NSS verify returns
  `CKR_MECHANISM_INVALID`, modules with native digest-cancel semantics keep
  them.
- NSS `C_DigestInit(NULL)` crashes the daemon by default. Test harnesses run
  with supervisor restart (`PROXY_FAIL_FAST_ON_DAEMON_CRASH=0`); production
  deployments that cannot tolerate this enable `sanitize_inputs` once it
  lands, or rely on multi-daemon partitioning (ADR-0007).
- Scope 2 extends the same fidelity to data-input pointers: the wire format
  must carry "pointer was NULL" and "claimed length N" independently, the
  daemon reconstructs the call verbatim, and `sanitize_inputs` gates the
  optional rejection path. This covers not only operation data but PIN inputs
  (NULL PIN = protected authentication path — currently conflated with an
  empty PIN), attribute templates, and NULL-able pointers embedded in
  mechanism/message parameter structs. Design + input-class taxonomy:
  umbrella `doc/plans/2026-06-11-transparent-forwarding-design.md`.
- Future "compatibility" fixes that would synthesize or translate a `CK_RV` on
  the default path are rejected by policy; they belong behind `sanitize_inputs`
  or in the backend module itself.

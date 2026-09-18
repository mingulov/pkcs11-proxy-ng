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
application must not be able to distinguish the shim from the real module
within the explicitly documented support/transport limits.

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
   native `CK_RV` is preserved when representable at the caller edge. This
   applies in both directions, including error values, subject to the explicit
   support/width limits below.
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
   daemon rejects spec-invalid inputs (including NULL mechanisms on classic
   init calls, NULL data pointers with non-zero length, and lengths beyond the
   `isize` boundary) with `CKR_ARGUMENTS_BAD` before they reach the module.
   NULL `C_MessageEncryptInit`/`C_MessageDecryptInit` remains the PKCS-defined
   message-operation cancel form and is valid in both modes. Daemon-side
   because that is the trust boundary the operator controls; a shim-side
   option would not protect the daemon from non-cooperating clients. Enabling
   it deliberately trades transparency for availability.

## v0.2 slot-event amendment (2026-09-13)

**Selected contract; implementation and native qualification pending.** v0.2
supports `C_WaitForSlotEvent` only with `CKF_DONT_BLOCK`. Blocking mode returns
local `CKR_FUNCTION_NOT_SUPPORTED` with zero provider attempts and no slot
output. Retain its ABI/function-list entry; do not implement a polling facade
or silently change flags/call counts. This is an explicit default-path support
limit, not a transparent refactor or an opt-in `sanitize_inputs` behavior.

The [native ownership contract](../release/native-mechanism-ownership.md)
defines the exact precedence: pointer/authentication/context checks, module
lifecycle, checked native flag width, mode, then sole-waiter contention.
Non-Open states refuse locally; overflow and supported-wait contention use
`CKR_FUNCTION_FAILED`. Representable DONT_BLOCK requests preserve every flag
bit for one native call under ordinary lifecycle exclusion through settlement.
No native wait overlaps native Finalize. Caller RV and successful virtual-slot
widths are checked; no truncation is allowed. Errors/NO_EVENT/local refusals
leave `pSlot` unchanged, even if native output was modified; successful slot
zero is valid when authorized/mapped.

Logical clients compete for one native application's pending-event flags;
logical Initialize does not create a new per-client bitmap. This is not full
native per-application event equivalence. Policy-suppressed/unmapped events
retain NO_EVENT. If a successful wait still needs a native authorization query
after seal, suppress output and return local NOT_INITIALIZED while retaining
its actual native OK observation; never issue a late native query. Already
safely authorized/mapped output may publish without another native call.
Disappeared contexts receive NOT_INITIALIZED. These rules apply to old clients
and custom service backends as well as direct FfiBackend calls.

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
- **(c) Message-API parameter embedded fields (class 5):** the registry-selected
  GCM, CCM, and Salsa/ChaCha shapes are transported structurally for
  MessageEncrypt/MessageDecrypt Init, one-shot, Begin, and Next. The shim binds
  each call to its active shape and exact client-native outer struct, and the
  daemon reconstructs a provider-native struct; raw outer bytes never cross
  the ABI boundary. Encrypt parameters support validated provider writeback,
  while Decrypt parameters are input-only. Sign/Verify parameters remain
  empty-only. A materialized unmodelled parameter, a present buffer or embedded
  extent beyond `MAX_SERIALIZABLE_BYTES`, or a writable parameter buffer that
  aliases another call buffer fails closed with `CKR_MECHANISM_PARAM_INVALID`.
  Unmodelled class-5 layouts, over-ceiling buffers, and writable-buffer aliasing
  therefore remain acknowledged transport limits rather than faithful raw
  forwarding paths.
- The constant `MAX_MECHANISM_PARAM_STRUCT_LEN` (64 KiB, renamed from
  `MAX_MECHANISM_PARAM_LEN`) bounds only parameter-STRUCT lengths; embedded
  data fields are bounded by `MAX_SERIALIZABLE_BYTES` (512 MiB). Legitimate
  AAD/seed/label/IV values larger than 64 KiB no longer hit the struct cap.
- **(d) Unallocatable output capacities (Wave 3.5 D7):** a claimed
  output-buffer capacity above `MAX_OUTPUT_BUFFER_BYTES` (512 MiB) on an
  exact byte-output call. The daemon answers `CKR_ARGUMENTS_BAD` at the
  allocation gate before native entry (stable; was: `CKR_HOST_MEMORY`).
  The exact provider call needs the full buffer to cross, so the claim is
  unforwardable — a bad argument, not a failed allocation. This mirrors
  Limits-(a) for absurd inputs and the parameter-roundtrip gate, and matches
  the `CKR_ARGUMENTS_BAD` member of the backend answer family for absurd
  claims. A genuine allocation failure under the cap still returns
  `CKR_HOST_MEMORY`. Residual divergences: backends that answer
  huge-but-allocatable claims with `CKR_BUFFER_TOO_SMALL` or
  function-specific range codes (`CKR_DATA_LEN_RANGE`,
  `CKR_SIGNATURE_LEN_RANGE`) cannot be matched without forwarding the exact
  call, which requires the full buffer; those stay documented limits.

## NULL output-length pointers

Output-bearing calls preserve all three native caller shapes through the
existing exact-output RPCs: a missing output-length pointer, an ordinary size
query, and a caller-provided output buffer. The additive
`OutputBufferSpec.length_pointer_null` field defaults to false for older wire
payloads. The shim captures both pointer classes without dereferencing a NULL
length pointer; the daemon reconstructs the actual NULL pointer only at the
provider FFI boundary and calls the provider once. The response preserves the
provider's exact `CK_RV`; its main-output envelope is canonically empty
(`returned_len = 0`, no value), is not written to caller memory, and does not
hide genuine mechanism, message-parameter, or KEM handle output produced by a
successful provider call.

`C_SignMessageNext` is the deliberate exception. Its NULL signature-length
form is the PKCS#11 feed/control call, represented by `request_signature =
false`; it remains on that feed path and is not reclassified as a missing-length
exact-output request.

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
  templates (class 3), and embedded mechanism-parameter pointers (class 4)
  remain deferred. For class 5, the modelled GCM, CCM, and Salsa/ChaCha message
  shapes follow the bounded structural contract above; only unmodelled layouts
  remain deferred.
- `sanitize_inputs` (Scope 2, daemon config, default OFF): rejects NULL
  data pointers with `len > 0` and NULL mechanisms on classic init calls with
  `CKR_ARGUMENTS_BAD` before the module is called. MessageEncrypt/MessageDecrypt
  NULL Init cancellation is accepted with sanitization both disabled and
  enabled. Known divergence: a sanitize-mode reject does NOT terminate the
  active backend operation the way a module-returned error would; applications
  relying on operation termination from a rejected call must not depend on
  `sanitize_inputs` for that behavior. This is an accepted trade-off
  (availability over full fidelity) documented here rather than silently fixed.
- Known bypass: the LEGACY `Encrypt`/`EncryptUpdate`/`Decrypt`/`DecryptUpdate`
  single-op handlers (`cipher.rs`) hardcode `CkInBuf::Bytes`, ignoring
  `*_null_len` and skipping `check_sanitize`, as do the 4 combined-update
  handlers (`sign_encrypt.rs`, `decrypt_digest.rs`) — 8 handlers total where
  both NULL-wire-fidelity and the sanitize gate are unwired. By contrast, the
  legacy Sign/SignUpdate/SignRecover/Verify/VerifyUpdate/VerifyFinal/
  VerifyRecover/Digest/DigestUpdate handlers DO read `*_null_len`, DO call
  `check_sanitize`, and DO reconstruct via `input_from_wire`. The asymmetry is
  acceptable: all unwired handlers are marked
  `// NOTE: legacy per-op RPC — not used by the shim` and are unreachable from
  normal shim use (the shim routes via `ByteOutputExact`); they are on the
  follow-up cleanup roster.
- Further "compatibility" fixes that synthesize or translate a default-path
  `CK_RV` require an explicit contract amendment like the bounded slot-event
  decision above, or belong behind `sanitize_inputs` or in the backend module.

## Rolling upgrade contract for pointer-safe message parameters

Authenticated wrap/unwrap use a distinct `authenticated_parameters` request
acknowledgment and `authenticated_output` response. The
`pointer_safe_authenticated_parameters` capability must be true before a new
client issues these calls. Upgrade daemons first. Old requests accept only
parameterless mechanisms and the explicitly modeled pointer-free IV byte
array; any structure requires the new contract and fails with
`CKR_FUNCTION_NOT_SUPPORTED` before native entry. No native structure image is
ever an output format. GOST key-wrap inputs retain their virtual caller handles
and pointers; their native input-only fields are never echoed.

Authenticated AES-GCM/CCM use `CK_*_MESSAGE_PARAMS` (including separate tag/MAC
buffers), as required by the PKCS#11 authenticated-function contract. The
classic `CK_*_WRAP_PARAMS` layouts cannot represent those outputs. The typed
path reuses bounded message-parameter conversion and writes only allowed
IV/tag or nonce/MAC buffers through caller pointer snapshots. Other materialized
authenticated shapes currently fail closed with `CKR_MECHANISM_PARAM_INVALID`.
The initial allowlist binds standard AEAD message shapes to their mechanism
identifiers, standard GOST key wrap to its input-only structure, and byte-array
IVs to the embedded inventory. Runtime vendor extensions require a reviewed
authenticated-output mapping; they cannot opt into native-image transport by
claiming an IV shape.
Extending that allowlist requires a source-grounded output-field contract.
Rejecting every pointer-bearing shape is the containment alternative; it would
also disable modeled AEAD and GOST forwarding. ABI-shaped sanitized blobs are
rejected because pointer widths, padding, and input handles are not portable
outputs. Native error effects beyond the existing exact-output contract and
completion-owned auditing after cancellation remain separate work.

Authenticated native readback validates an immutable fieldwise input snapshot
before extracting output or making a second convenience-call invocation. This
includes the mechanism identifier and outer pointer/length even for parameterless
and byte-array inputs, every GOST pointer/length/handle and OID/UKM input byte,
and AEAD input fields and fixed nonce/IV prefixes. Only explicitly permitted
owned IV/nonce and tag/MAC effects survive sizing. Native padding is never
compared. Rebuilding parameters between calls is an alternative, but requires
the same precise output-effect allowlist and additional allocations.

A successful authenticated unwrap gains a pending native-object cleanup owner
before fallible ancillary output validation, both inside the FFI adapter and at
the server's custom-backend result boundary. Valid success transfers ownership;
rejection attempts `C_DestroyObject` once. Failed destruction retains the native
identity and cleanup outcome in a private backend/service-lifetime quarantine
and blocks further authenticated unwrap creation with `CKR_DEVICE_ERROR`.
Quarantine is not exposed as a virtual handle or logged payload. It is in-memory
state, not a durable recovery journal; restarting does not establish that a
possibly persistent token object was removed. Operator/provider reconciliation
is required before restoring service. Automatic retries are deliberately absent
because session/object handles can become stale. Accepting mutated unwrap input
fields without validation would avoid this particular rejection, but would not
cover invalid output from arbitrary backends; explicit cleanup ownership covers
both boundaries without weakening validation. General cancellation and audit
divergence remain separate lifecycle work.

**Selected owner-migration amendment (2026-09-13; not yet implemented):**
Preallocate the created-object claim before Unwrap, record a defined successful
handle infallibly before readback, and perform rejection cleanup explicitly
under the existing session guard. Claim Drop makes no native call or allocation;
unwind parks the claim/frame for controlled settlement, without retrying an
uncertain destruction. FFI valid-result handoff disarms its claim once before
the server/custom-backend boundary assumes cleanup ownership outside those
guards. No recursive public-backend call or double destruction is permitted.
The original cleanup guarantee remains; unwind cleanup timing changes from
implicit Drop to explicit settlement. Native memory retirement still does not
prove persistent token-object deletion.

- Upgrade daemons before shims/clients. A new daemon accepts an old client's
  omitted shape only for the genuinely legacy-safe case: no outer envelope, no
  structured message parameter, and a type-only mechanism with empty
  `mechanism.params`. Old-client raw, structured, dual, or otherwise
  materialized parameter requests fail before provider invocation.
- A new shim/client treats an absent
  `pointer_safe_message_parameters` capability as false and returns
  `CKR_FUNCTION_NOT_SUPPORTED` before parsing caller parameters or issuing a
  stateful message RPC. Thus a new client does not probe an old daemon by
  mutating provider state.
- Response shape, envelope, and structured-variant acknowledgements are
  integrity checks for a responder that advertised the capability. They are
  not feature detection and do not replace the pre-call capability gate. Once
  both edges advertise and use the capability, the full shape, envelope, and
  acknowledgement contract above applies to every safe message path.

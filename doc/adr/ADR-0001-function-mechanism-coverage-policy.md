# ADR-0001: Function and Mechanism Coverage Policy

## Status
Proposed

## Context
The Rust PKCS#11 Remote Proxy forwards PKCS#11 operations from clients to a
backend over gRPC/protobuf. This requires the proxy to serialize and
deserialize every function call, every mechanism parameter struct, and every
attribute template that crosses the wire.

PKCS#11 3.2 defines roughly 80 functions, ~480 mechanisms, and dozens of parameter structures of varying complexity. The proxy cannot safely forward data it does not understand because:

1. **Pointer-bearing structs cannot be blindly serialized.** Many mechanism parameter structures (e.g., `CK_GCM_PARAMS`, `CK_ECDH1_DERIVE_PARAMS`) contain pointers to variable-length buffers. Forwarding raw bytes without understanding the layout produces memory-safety violations or silent data corruption on the receiving side.

2. **ABI differences across architectures and PKCS#11 versions.** Field sizes, alignment, and struct layouts differ between 32-bit and 64-bit systems and between PKCS#11 2.40 and 3.x. A transparent byte-forwarding proxy inherits all of these hazards.

3. **The PRD (sections 7.4 and 7.5) requires an explicit allow-list model.**
   The project must publish supported functions, mechanisms, parameter
   structures, and attributes; must reject unsupported mechanisms rather than
   forwarding opaque data; and must intersect backend discovery with the
   allow-list before exposing capabilities to clients.

4. **Phase 1 is intentionally narrower than the full standard surface.** The
   PRD commits Phase 1 to an explicit, tested subset of PKCS#11 2.40, 3.0, and
   3.2, not to blanket support for every standard function on day one.

This ADR establishes the coverage policy that governs which PKCS#11 functions and mechanisms the proxy supports, how unsupported items are handled, and how coverage expands over time.

## Decision

### 1. Function Coverage

Phase 1 supports an **explicit, published subset** of standard PKCS#11
functions. The long-term target is complete coverage of all standard PKCS#11
functions from 2.40 through 3.2. However, the project does not define protobuf
RPCs for the full surface up front — it begins with a seed set and expands
iteratively.

The initial seed subset is:

| Category | Phase 1 seed set |
|----------|------------------|
| Shim-local introspection | `C_GetFunctionList`, `C_GetInterfaceList`, `C_GetInterface` |
| General | `C_Initialize`, `C_Finalize`, `C_GetInfo` |
| Slot/token discovery | `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_GetMechanismList`, `C_GetMechanismInfo` |
| Sessions/auth | `C_OpenSession`, `C_CloseSession`, `C_CloseAllSessions`, `C_GetSessionInfo`, `C_Login`, `C_Logout` |
| Object discovery | `C_FindObjectsInit`, `C_FindObjects`, `C_FindObjectsFinal`, `C_GetAttributeValue` |
| Signing/verification | `C_SignInit`, `C_Sign`, `C_SignUpdate`, `C_SignFinal`, `C_VerifyInit`, `C_Verify`, `C_VerifyUpdate`, `C_VerifyFinal` |
| Key management / RNG | `C_GenerateKeyPair`, `C_GenerateRandom` |

The following groups were initially deferred but are now implemented
(see implementation plan docs/superpowers/plans/2026-03-14-pkcs11-3x-functions.md):

- `C_LoginUser`, `C_SessionCancel`, `C_GetSessionValidationFlags` (session extensions)
- Message-based 3.0 functions (`MessageEncrypt*`, `MessageDecrypt*`, `MessageSign*`, `MessageVerify*`)
- `C_EncapsulateKey`, `C_DecapsulateKey` (KEM)
- `C_VerifySignatureInit`/`VerifySignature`/`VerifySignatureUpdate`/`VerifySignatureFinal`
- `C_WrapKeyAuthenticated`, `C_UnwrapKeyAuthenticated`
- `C_AsyncComplete` (polling), `C_AsyncGetID` (returns `CKR_STATE_UNSAVEABLE`), `C_AsyncJoin` (returns `CKR_SAVED_STATE_INVALID`)
- wrap/unwrap/derive flows
- token-initialization and PIN-administration functions
- object creation/copy/destroy beyond what is required for the validated Phase 1
  workflows

**Implementation note (2026-05-16):** The vendored OASIS Markdown includes six
extensible-output digest functions, `C_DigestXof*`, but `cryptoki-sys` 0.5.0
does not expose corresponding fields in `CK_FUNCTION_LIST`,
`CK_FUNCTION_LIST_3_0`, or `CK_FUNCTION_LIST_3_2`. The proxy therefore treats
them as explicit spec-only ABI gaps, not as implemented or stubbed functions.
The shim must not add custom function-list layouts or out-of-band named exports
for these APIs, because portable PKCS#11 callers discover functions through the
standard function list and a custom layout would not be ABI-compatible with
current consumer bindings. Support can be revisited when the local ABI binding
exposes a standard function-list surface for these functions.

The published support table may expand beyond this seed set, but nothing
outside the seed set is assumed to exist by the protocol, CI, or compatibility
matrix until it is explicitly added.

**Attribute templates** (`CK_ATTRIBUTE` arrays used in `C_FindObjectsInit`,
`C_GetAttributeValue`, and later object-management calls) are modeled as a core
shared protobuf type. Known attributes use typed serialization. Vendor-defined
or unknown attributes may only use a raw-bytes value form when the wire
representation is just `(type, value-bytes)` and the attribute is explicitly
allow-listed. This exception does not relax the no-raw-forward rule for
pointer-bearing mechanism parameters.

### 2. Mechanism Handling Model

Mechanisms are handled based on their parameter requirements at **operation
time**, not by static classification alone.

> **Implementation note (2026-03-15, corrected 2026-09-21):** The
> mechanism-to-parameter-shape mapping is config-driven, defined in
> `mechanism_params.toml`. The **daemon** reads it at startup (the embedded
> default applies when `[mechanisms].config_path` is unset), publishes the
> payload on every `GetBackendInterfaces` RPC, and reloads on SIGHUP; shims
> consume it during `interface_probe::ensure_probed()` — the shim does not
> load registry files at `C_Initialize`. Vendor mechanisms are added via the
> daemon override file (`PKCS11_PROXY_MECHANISMS` survives only as the shim
> fallback override when the daemon is unreachable or omits the field). See
> the design spec at `docs/superpowers/specs/2026-03-15-mechanism-registry-design.md`.

#### Parameterless use — always forwarded

When a caller invokes an operation (e.g., `C_SignInit`, `C_EncryptInit`) with
`pParameter == NULL` and `ulParameterLen == 0`, the proxy forwards the request
to the backend regardless of whether the mechanism is in any explicit list.
This is safe because there are no parameter bytes to serialize or interpret.

This rule automatically enables all parameterless mechanisms — including
mechanisms added in future PKCS#11 revisions — with zero proxy changes.
Some mechanisms that normally take parameters also permit `NULL/0` for
default behavior (e.g., certain key-wrap modes); these benefit from the same
rule when the caller uses the parameterless form.

#### Explicitly modeled parameters — serialized and forwarded

Mechanisms with parameters that the proxy has explicitly modeled receive
field-by-field serialization. Each parameter structure gets a protobuf message
definition that resolves all pointers and variable-length buffers into protobuf
`bytes` or nested messages.

Explicitly modeled mechanisms are rolled out iteratively and prioritized by
real-world usage:

| Priority | Parameter structures | Mechanisms covered | Rationale |
|----------|--------------------|--------------------|-----------|
| P0 | `CK_RSA_PKCS_PSS_PARAMS`, `CK_RSA_PKCS_OAEP_PARAMS` | RSA-PSS sign/verify, RSA-OAEP encrypt/decrypt | Design-partner PKI signing |
| P1 | `CK_GCM_PARAMS` | AES-GCM | Authenticated encryption, if Phase 1 validation requires it |
| P1 | `CK_ECDH1_DERIVE_PARAMS` | ECDH key derivation | Common key agreement |
| P2 | `CK_CCM_PARAMS`, `CK_HKDF_PARAMS`, `CK_SP800_108_KDF_PARAMS` | AEAD and KDF flows | Broader modern-crypto support |
| P2 | `CK_GCM_MESSAGE_PARAMS`, `CK_CCM_MESSAGE_PARAMS`, `CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS` | Message-based AEAD | Per-message nonce/tag for 3.0 message APIs |
| P2 | PQC-related parameter structures (as defined in 3.2) | ML-KEM, ML-DSA, SLH-DSA, etc. | Future PQC readiness |
| P3 | `CK_TLS12_KEY_MAT_PARAMS`, `CK_TLS_MAC_PARAMS`, `CK_SKIPJACK_*`, `CK_WTLS_*`, `CK_CMS_SIG_PARAMS`, `CK_CT_KIP_PARAMS` | TLS offload and exotic/deprecated mechanisms | Completeness; lowest priority |

The initial modeled set is `CKM_RSA_PKCS_PSS` and `CKM_RSA_PKCS_OAEP`.
`CKM_AES_GCM` is a planned early extension, not a guaranteed Phase 1 baseline.

#### Unmodeled parameters — rejected immediately

If a caller supplies a mechanism with `pParameter != NULL || ulParameterLen != 0`
and that mechanism's parameter structure has **not** been explicitly modeled, the
proxy rejects the operation immediately with **`CKR_MECHANISM_PARAM_INVALID`**.

`CKR_MECHANISM_PARAM_INVALID` is more precise than `CKR_MECHANISM_INVALID`
because the proxy does recognize the mechanism (the backend supports it); it is
the parameter serialization that is unsupported. This distinction follows the
PKCS#11 error semantics in the specification's function return values section.

The rejection happens client-side (in the shim or client library) when possible,
avoiding a round trip to the daemon for operations that would inevitably fail.

### 3. Parameter Complexity Categories

The standard mechanism set breaks down into these parameter complexity
categories, which inform implementation effort:

| Category | Serialization approach |
|----------|------------------------|
| Parameterless (`NULL`) | Allow-list plus no parameter handling |
| Scalar / fixed-IV (no pointers) | Simple protobuf scalar fields |
| Simple struct (scalar fields only, e.g., `CK_RSA_PKCS_PSS_PARAMS`) | One protobuf message per struct |
| Pointer-bearing struct (e.g., `CK_GCM_PARAMS`, `CK_ECDH1_DERIVE_PARAMS`) | Explicit field-by-field modeling; pointers become `bytes` fields |
| Nested / complex (SSL/TLS, SP800-108, CMS) | Recursive protobuf message modeling |
| Deprecated / exotic (Skipjack, WTLS, CT-KIP) | Same as above; scheduled last |

### 4. Mechanism Discovery — Two Modes

The proxy supports two mechanism discovery modes, configurable per deployment.
Both modes enforce the same operation-time safety rules (section 2); they differ
only in what `C_GetMechanismList` and `C_GetMechanismInfo` report.

> **Implementation note (2026-03-15):** Mechanism filtering is now
> client-side (in the shim), not server-side. The `MechanismFilter` has been
> removed from the server. The server is a pure proxy for
> `C_GetMechanismList` and `C_GetMechanismInfo`.

#### Filtered mode (opt-in for strict environments)

The proxy computes the advertised mechanism list as:

```
advertised = backend_mechanisms INTERSECT proxy_fully_supported_mechanisms
```

Where `proxy_fully_supported_mechanisms` includes mechanisms whose parameters
are either always `NULL/0` (parameterless) or explicitly modeled.

**Invariant:** If a mechanism appears in the filtered `C_GetMechanismList`
response, the proxy guarantees it can correctly handle that mechanism for every
currently supported PKCS#11 operation, including all valid parameter forms.

`C_GetMechanismInfo` is filtered consistently: the proxy returns info only for
mechanisms in the advertised set.

Filtered mode may be enabled via `mechanism_discovery = "filtered"` for
deployments that require strict discovery guarantees — i.e., every mechanism
in `C_GetMechanismList` is fully executable through the proxy for all valid
parameter forms.

#### Transparent mode (default for all clients including the shim)

`C_GetMechanismList` and `C_GetMechanismInfo` pass through the backend's full
mechanism set without filtering. All clients — including the PKCS#11 shim —
receive the real backend view.

The native client API also exposes a separate **proxy support query** that
indicates, for each mechanism, whether the proxy can serialize its parameters.
This lets callers distinguish "backend supports it" from "proxy can handle it
end-to-end."

Transparent mode is the default because hiding mechanisms at discovery time
causes confusing behavior — clients cannot see mechanisms that the proxy can
actually handle (e.g., all parameterless mechanisms). Operation-time safety
(§2, §5) still prevents unsafe parameter forwarding. Filtered mode remains
available for deployments that require strict discovery guarantees.

#### Configuration

```toml
[proxy]
# "filtered"    = C_GetMechanismList shows only proxy-supported mechanisms
#                 (opt-in for strict environments)
# "transparent" = C_GetMechanismList shows all backend mechanisms
#                 (default — operation-time safety still rejects unmodeled params)
mechanism_discovery = "transparent"
```

### 5. The No-Raw-Forward Rule

**The proxy NEVER forwards raw mechanism parameter bytes it does not
understand.** This rule is absolute and applies regardless of discovery mode,
transport optimization, or vendor-extension pressure. Violations would silently
introduce memory-safety, correctness, and interoperability hazards that
contradict the project's core safety thesis (PRD section 7.5).

The operation-time enforcement is:

- `pParameter == NULL && ulParameterLen == 0` → **forward** (safe, no parameter
  data to interpret).
- `pParameter != NULL || ulParameterLen != 0`, mechanism explicitly modeled →
  **serialize and forward**.
- `pParameter != NULL || ulParameterLen != 0`, mechanism **not** modeled →
  **reject** with `CKR_MECHANISM_PARAM_INVALID`.

The check uses `pParameter != NULL || ulParameterLen != 0` (not just length)
because some malformed calls may set only one of the two fields, and because
message-based PKCS#11 3.x APIs can use the mechanism parameter for input/output,
making opaque forwarding even less acceptable.

### 6. Iteration and Expansion Strategy

Coverage expands through these steps:

1. **Identify the target mechanism's parameter structure** from the PKCS#11 specification.
2. **Define a protobuf message** for the parameter structure, resolving all pointers to `bytes` or nested messages.
3. **Implement serialization (client-side):** C struct to protobuf.
4. **Implement deserialization (server-side):** protobuf to C struct, with validation of buffer lengths and field constraints.
5. **Add the mechanism to the proxy's modeled set** so it appears in filtered-mode `C_GetMechanismList` results and is accepted with parameters at operation time.
6. **Write round-trip tests** that verify serialization fidelity for edge cases (empty buffers, maximum lengths, zero-length IVs, etc.).

The initial iteration targets the design partner's actual mechanism usage: RSA
signing, ECDSA, SHA-family digests, and key-pair generation first. AES-GCM,
RSA-OAEP, and other parameterized mechanisms follow only if the published Phase
1 support table includes them.

**Goal:** Over time, the project may grow toward broad standard coverage, but
each addition still requires explicit modeling, tests, and support-table
publication.

### 7. Open Questions

- **Runtime mechanism set changes.** The backend's mechanism set can change at runtime (HSM firmware upgrade, module reload, token insertion/removal). The proxy must detect and propagate these changes. The detection strategy (polling, event-driven via `C_WaitForSlotEvent`, or session-scoped caching with TTL) is deferred to a future ADR.

- **Vendor-defined mechanisms.** PKCS#11 allows vendor-defined mechanism types (`CKM_VENDOR_DEFINED` and above). The proxy's no-raw-forward rule means vendor mechanisms cannot be supported without explicit parameter modeling. A vendor-extension registration mechanism may be needed if design partners require vendor-specific mechanisms.

- **Vendor-defined attributes.** Raw attribute values are safer than raw
  mechanism-parameter structs because their wire shape is already
  `(type, value-bytes)`. Even so, the project still needs size limits,
  allow-listing, and rules for which vendor attributes may appear in Phase 1.

## Consequences

### What becomes easier

- **Safety is structural.** The no-raw-forward rule guarantees that clients
  never encounter silent serialization failures or corrupted parameter data. In
  filtered mode, advertised mechanisms are fully supported. In transparent mode,
  unsupported parameters are caught immediately at operation time with a clear
  error.

- **Parameterless mechanisms are free.** All parameterless mechanisms — including
  those added in future PKCS#11 revisions — work automatically without proxy
  changes. This covers roughly 40% of the ~480 mechanisms in PKCS#11 3.2.

- **Incremental delivery is well-defined.** New parameterized mechanisms are
  added by implementing a protobuf message and adding to the modeled set. Each
  addition is independently testable.

- **Dual discovery modes serve different needs.** Transparent mode (the default)
  gives all clients full backend visibility. Filtered mode is available for
  deployments that need strict discovery guarantees. The native client API
  additionally exposes proxy-support metadata per mechanism.

- **Cross-platform correctness.** Explicit field-by-field serialization
  eliminates ABI hazards across architectures, operating systems, and PKCS#11
  versions.

### What becomes harder

- **Parameterized mechanism coverage is initially narrow.** Until parameter
  structures are modeled, the proxy rejects parameterized uses of those
  mechanisms even if the backend supports them. This is an intentional trade-off:
  safety over breadth.

- **Initial function coverage is narrow.** Some standard functions remain
  deliberately out of scope in Phase 1 even if the backend supports them. This
  keeps the protocol and compatibility matrix aligned with real workflows.

- **Every new parameterized mechanism requires implementation work.** There is
  no shortcut for pointer-bearing parameter structures. Each requires a protobuf
  definition, serialization code, deserialization code, and tests.

- **Vendor-defined mechanisms with parameters are blocked by default.**
  Organizations using vendor-specific PKCS#11 extensions will need explicit proxy
  support, which may lag behind vendor releases. Vendor-defined parameterless
  mechanisms work automatically.

### What becomes riskier

- **Transparent mode can mislead applications.** In transparent mode (the
  default), an application may see a mechanism in `C_GetMechanismList`, attempt
  to use it with parameters, and receive `CKR_MECHANISM_PARAM_INVALID`. This is
  a clear error, but some applications may not handle it gracefully. Filtered
  mode (`mechanism_discovery = "filtered"`) is available for environments where
  this is unacceptable.

- **Coverage gaps may block adoption.** If a prospective user requires a
  parameterized mechanism that is not yet modeled, the proxy is unusable for
  that workflow until implementation catches up. The iteration priority must stay
  aligned with real-world demand.

- **Specification ambiguity in parameter structures.** Some PKCS#11 parameter
  structures have underspecified semantics (e.g., optional fields,
  version-dependent layouts). Modeling these correctly requires careful
  specification reading and interoperability testing against real backends.

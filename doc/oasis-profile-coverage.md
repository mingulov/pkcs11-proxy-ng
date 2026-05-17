# OASIS PKCS#11 Profile Coverage Mapping

**Date:** 2026-05-17 (updated for OASIS source-discrepancy guardrails)

## Purpose

Maps OASIS PKCS#11 specification profile areas to this project's validation
coverage. This is a living document updated as test coverage expands.

## Source-Derived Inventory

Use `scripts/oasis-coverage-inventory.py` for the optional source-grounded
function, interface, and mechanism matrix. When an OASIS tree is already
supplied through `PKCS11_PROXY_NG_OASIS_ROOT` or the umbrella workspace
(`../doc/oasis-tcs-pkcs11/working/doc/spec/`), the script reads that Markdown
and the matching published headers
(`../doc/oasis-tcs-pkcs11/published/{2-40-errata-1,3-00,3-01,3-02}/pkcs11t.h`).
It compares those optional sources with local function-list tables, proto RPCs,
backend trait methods, client methods, shim dispatch functions, the generated
Rust mechanism inventory, and local `../pkcs11-check/artifacts/*/coverage.json`
evidence.

The inventory treats OASIS as the source family, not as one perfectly
consistent file. Working Markdown, published headers, and local `cryptoki-sys`
bindings can disagree or omit details from one another. When that happens, the
matrix must keep the discrepancy explicit with source-specific reasons such as
`cryptoki_sys_missing_function_list_field`,
`oasis_working_spec_lacks_published_numeric_value`, alias classification, or
placeholder exclusion. Do not infer numeric mechanism IDs, ABI structs, or
function-list entries from prose alone.

The embedded mechanism-parameter registry follows the same rule: default
entries use published `CKM_*` values only. It does not assign project-local
placeholder IDs for working-spec names, ambiguous EC dual-party structures, or
unsafe-to-read Signal structures. For example, `CKM_ECMQV_DERIVE` maps to the
published `CK_ECMQV_DERIVE_PARAMS` shape, while `CK_ECDH2_DERIVE_PARAMS`
remains a typed transport/helper shape because OASIS publishes no separate
`CKM_ECDH2_DERIVE` value.

Current generated summary:

| Metric | Count |
|--------|-------|
| Vendored OASIS Markdown files | 107 |
| Spec functions found in Markdown | 110 |
| Published OASIS v3.2 function-list entries | 104 |
| CK_FUNCTION_LIST / 3.0 / 3.2 function fields represented by `cryptoki-sys` | 104 |
| Represented functions with local test citations | 104 |
| Standard `PKCS 11` interface catalog entries tracked | 3 |
| Modeled mechanism parameter shapes | 79 |
| Spec mechanism parameter structs tracked | 64 |
| Message parameter shapes | 3 |
| Intentional MockBackend inherited trait defaults | 2 (`C_GetFunctionStatus`, `C_CancelFunction`) |
| Spec functions not exposed by current function-list tables | 6 (`C_DigestXof*`) |
| Official published mechanism values | 463 |
| Rust generated official mechanism values checked | 463 |
| Spec mechanism names found in Markdown | 366 |
| Working-spec mechanism names without published numeric values | 6 |
| Published-header mechanism names/aliases absent from working Markdown | 119 |
| Mechanism-info flag matrix entries | 485 |
| Source-grounded mechanism-info flag entries | 358 |
| Mechanism-info flag rows without source workflow evidence | 121 |
| Header-only mechanism-info flag gaps | 119 |
| Working-Markdown mechanism-info flag gaps without workflow rows | 2 |
| Local pkcs11-check coverage artifacts read | 14 |
| Official mechanism values from published headers | 463 |
| Official mechanism names/aliases in matrix | 479 |
| Official mechanism names/aliases with provider artifact coverage | 315 |
| Official mechanism names/aliases absent from provider artifacts | 164 |

The generated JSON also emits a top-level `completion_gap_summary` for audit
triage. It derives `missing_local_test_citation_counts` from the function,
parameter-shape, message-parameter, mechanism-info flag, and MockBackend
coverage matrices, separates `actionable_mockbackend_semantic_gap_count` from
`intentional_no_source_workflow_rejection_count`, emits
`intentional_unsupported_function_list_gap_names` for XOF function-list
omissions with a local ABI decision, emits
`intentional_unsupported_numeric_value_gap_names` for working-spec mechanisms
without published numeric values, emits
`intentional_unsupported_workflow_gap_names` for no-source workflow rows with
explicit rejection decisions, and groups the remaining explicit source gaps:
provider gaps and missing parameter-shape coverage. It also emits
`strict_completion_open_items`, `strict_completion_open_item_counts`,
`internal_completion_open_item_count`, and `strict_completion_open_item_count`
so that a zero actionable-MockBackend count cannot be confused with goal
completion. This summary is a navigation aid over the matrices, not a
standalone completion signal.

The six `C_DigestXof*` functions are documented in the vendored
`message_digesting_functions.md` but are not present in the current
OASIS published v3.2 `pkcs11f.h` function list or the current `cryptoki-sys`
0.5.0 function-list structs used by this project. The project does not add
out-of-band named shim exports or custom `CK_FUNCTION_LIST_3_2` layouts for
them, because callers discover portable PKCS#11 functions through the standard
function list and changing that struct would break ABI compatibility. They are
therefore tracked as explicit spec-only gaps with the generated reason
`cryptoki_sys_missing_function_list_field`, not silently counted as
implemented. Each XOF row also carries a structured `local_abi_decision`
object with the policy
`do_not_add_out_of_band_exports_or_custom_function_list_layout`, evidence from
the working digest spec, all published `pkcs11f.h` headers checked, and the
local function-list field table. The rows cite both the generated inventory
guard and an ignored loaded-shim export-surface test proving the shim does not
publish out-of-band `C_DigestXof*` symbols while preserving the standard
`C_GetFunctionList` export. This records the OASIS source inconsistency as a
deliberate ABI choice rather than a missing shim/server path.

The interface matrix tracks the standard `PKCS 11` interfaces returned by the
shim catalog: 2.40 (`CK_FUNCTION_LIST`), 3.0 (`CK_FUNCTION_LIST_3_0`), and 3.2
(`CK_FUNCTION_LIST_3_2`). It cites the OASIS `CK_INTERFACE` and
`C_GetInterface*` spec sections plus loaded shim tests proving catalog order,
version selection, and the default 3.2 interface. The generated interface rows
also mark MockBackend default capability and cite the backend unit test proving
it reports the same 2.40/3.0/3.2 set by default, so loaded-shim tests exercise
the 3.2 function list through the normal endpoint-probed catalog rather than a
static fallback.

`C_GetFunctionList`, `C_GetInterfaceList`, and `C_GetInterface` are local C ABI
entry points served by the shim catalog itself. They intentionally have no
proto, client, server, or backend trait path. The generated function matrix
marks them with `shim_local_function_catalog_entrypoint` and cites the loaded
shim interface tests instead of leaving those proxy-layer columns ambiguous.

`C_GetFunctionStatus` and `C_CancelFunction` are legacy parallel-operation
status APIs from the 2.40 function list. `MockBackend` intentionally inherits
the `Pkcs11Backend` trait defaults for these two methods, which return
`CKR_FUNCTION_NOT_PARALLEL`, rather than simulating legacy parallel execution.
The generated `mock_backend_default_trait_decisions` matrix derives this from
the trait implementation, maps the inherited defaults back to official C
functions, and cites the backend unit test that pins the return value.

Every represented function row now cites local test evidence. The function
matrix cites proxy-layer consistency tests, shim C ABI function-list tests, and
shim panic-boundary tests for proxy-routed functions; shim-local catalog
entrypoints cite the loaded interface tests directly. The generator also emits
`local_tests_missing` in JSON for function, MockBackend default-decision,
mechanism-parameter shape, message-parameter shape, and mechanism MockBackend
coverage rows so stale test-name citations fail the local quality gate instead
of becoming silent documentation drift.
For 3.0/3.2 provider-gap APIs, the function matrix also cites behavioral gRPC
tests for async completion/status, KEM encapsulate/decapsulate, authenticated
wrap/unwrap, and message init/one-shot/begin/next/final flows instead of
relying only on function-list or handler-presence checks. The message
Begin/Next rows additionally cite an ignored loaded-shim C ABI test that calls
the 3.2 function list with caller-owned raw buffers and `CK_GCM_MESSAGE_PARAMS`
stack structs.

The mechanism parameter-shape matrix compares every `CkMechanismParams` enum
variant against the Rust parameter struct, OASIS `CK_*PARAMS` source evidence,
proto message, `Mechanism.params` oneof field, backend FFI reconstruction, shim
read support, shim writeback support, and known mutable-output behavior. All
concrete spec parameter structs are either modeled, classified as message
parameters, or classified as aliases/placeholders. `CK_KMAC_PARAMS` and
`CK_MU_GEN_PARAMS` are modeled as typed mechanism parameter shapes.
`CK_EXTRACT_PARAMS` is modeled as the typed `ExtractParams` shape for
`CKM_EXTRACT_KEY_FROM_KEY`.

Every safe represented mechanism-parameter shape now cites local test evidence
in the generated matrix. That includes raw IV parameters, scalar
`CK_OBJECT_HANDLE` parameters, `CK_KEY_DERIVATION_STRING_DATA`, and
`CK_SIGN_ADDITIONAL_CONTEXT`, with proto round-trips, backend FFI
reconstruction tests, and shim C-stack read tests where applicable.
Unsupported raw and vendor-specific transport-only parameter variants are also
exercised: the backend FFI reconstruction path rejects them with
`CKR_MECHANISM_PARAM_INVALID`, and the generated matrix cites that test beside
their explicit unsupported reasons. This keeps those rows intentional without
claiming a safe OASIS ABI mapping where the local sources do not provide one.

The working `chacha20_salsa20_poly1305.md` prose mentions
`CK_CHACHA20POLY1305_PARAMS`, but its C definition and the published OASIS
headers define `CK_SALSA20_CHACHA20_POLY1305_PARAMS`. The generated inventory
therefore records `CK_CHACHA20POLY1305_PARAMS` as an explicit
working-spec prose alias for the already modeled
`Salsa20ChaCha20Poly1305Params` shape, not as a missing ABI struct.

The working key-management prose uses `CK_XXX_MESSAGE_PARAMS` as a placeholder
for mechanism-specific message parameter structs such as `CK_GCM_MESSAGE_PARAMS`
and `CK_CCM_MESSAGE_PARAMS` in authenticated wrap/unwrap discussion. The
generated inventory records it under placeholder exclusions, not as a missing
concrete C ABI struct.

Some official parameter structs are represented in Rust/proto/backend FFI but
are deliberately not parsed into typed values by the shim from caller-owned C
stack memory. `CK_X3DH_*`, `CK_X2RATCHET_*`, and `CK_CMS_SIG_PARAMS` contain
byte or string pointers without sufficient bounded length information for a
safe generic shim read. Their matrix rows carry `shim_read_decision.policy =
do_not_parse_unbounded_caller_pointers_in_shim` and
`shim_read_decision.caller_visible_outcome =
direct_shim_parameterized_calls_return_CKR_MECHANISM_PARAM_INVALID`. The raw
mechanism reader preserves bytes if it is reached, but direct shim C ABI
entrypoints validate first and reject these parameterized mechanisms instead of
guessing pointer lengths. This is covered both by shim helper unit tests and by
an ignored loaded-shim C ABI test that calls through real function-list
pointers with caller-owned `CK_CMS_SIG_PARAMS`, `CK_X3DH_*`, and
`CK_X2RATCHET_*` stack structs.
MockBackend still performs source-grounded semantic checks on the typed
transport representation where OASIS names real object-handle fields: X3DH and
X2Ratchet derive parameters reject invalid referenced key handles, but
lengthless byte-pointer fields are treated as opaque transported data. CMS
signature workflows validate a nonzero `certificateHandle`, while preserving
`CK_OBJECT_HANDLE(0)` as the local representation of the spec's absent
certificate case. `CKM_CONCATENATE_BASE_AND_KEY` validates its scalar
`CK_OBJECT_HANDLE` parameter, and CT-KIP validates `hKey` for derive/MAC while
leaving the same field unused for `CKM_KIP_WRAP`, matching the mechanism prose.
The EC/X9.42 dual-party derive shapes validate the source-defined
`hPrivateData` handle, and their MQV variants also validate the source-defined
`publicKey` handle.

Message-operation parameter structs are tracked in a separate message-parameter
matrix because they are not `CK_MECHANISM` parameters. That matrix currently
covers `CK_GCM_MESSAGE_PARAMS`, `CK_CCM_MESSAGE_PARAMS`, and
`CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS`, including proto fields, backend FFI
message conversion, shim read support, shim writeback support, and mutable
output buffers. It also cites MockBackend typed exact-path tests that return
synthetic ciphertext/signature bytes plus structured parameter writeback for
GCM, CCM, and Salsa/ChaCha message params.

The working Markdown also names six mechanism tokens that do not have numeric
`CKM_*` values in the vendored OASIS published v2.40, v3.0, v3.1, or v3.2
headers: `CKM_KMAC128`, `CKM_KMAC256`, `CKM_ML_DSA_EXTERNAL_MU`,
`CKM_ML_DSA_EXTERNAL_MU_GEN`, `CKM_SHAKE_128`, and `CKM_SHAKE_256`. These are
tracked as explicit mechanism gaps with the generated reason
`oasis_working_spec_lacks_published_numeric_value`, because `MockBackend` can
only advertise mechanisms that have a concrete `CK_MECHANISM_TYPE` value. Their
matrix rows also carry `local_numeric_decision.policy =
do_not_assign_project_local_ckm_values_for_working_spec_names`, so future
readers can see that the project is deliberately waiting for published OASIS
values instead of assigning local numbers that could collide later.

The inverse discrepancy is also explicit: 119 mechanism names or aliases have
published OASIS header values but are not named by the vendored working
Markdown. Those rows are still official, represented mechanisms because the
published headers provide concrete `CK_MECHANISM_TYPE` values and version
metadata. The generated matrix marks them with
`source_discrepancy_reason = oasis_published_header_not_in_working_markdown`
instead of classifying them as implementation-only behavior.
The mechanism rows also expose published-header annotations such as
`Historical` and `Deprecated` per mechanism name/alias, so old-but-official
2.40 mechanisms remain visible as official coverage rows without pretending
the current working Markdown supplies modern workflow tables for them.

Mechanism-info flag coverage is stricter than generic MockBackend workflow
coverage. The generated matrix only marks a mechanism's expected
`CK_MECHANISM_INFO` flags as source-grounded when the vendored OASIS sources
provide workflow evidence for that mechanism or family. Mechanisms that lack
that evidence remain represented in the official catalog when they have
published values, but their flag rows carry `no_source_workflow_evidence`,
`no_source_workflow_flags_available`, and a structured `source_gap_decision`
with `policy =
do_not_infer_ckf_flags_from_mechanism_name_or_header_presence`.

The no-source rows are split by source-gap class. 119 are header-only
mechanism names or aliases that are absent from the working Markdown, such as
`CKM_BATON_KEY_GEN`. 2 are mechanisms named in working Markdown but lacking
source workflow flags: `CKM_CAMELLIA_CTR` and `CKM_DES_CBC`. Both classes cite the
specific Markdown/header evidence checked, which makes OASIS omissions visible
instead of letting the simulator silently invent flags from names, legacy
conventions, or broad synthetic workflow tests. MockBackend pins this as a
tested zero-flag policy for representative mechanisms such as
`CKM_BATON_KEY_GEN`, `CKM_CAMELLIA_CTR`, and `CKM_CAST5_CBC`; the gRPC daemon
lane checks the same policy through client-to-backend transport, and the
loaded-shim C ABI lane checks `C_GetMechanismInfo` for
`CKM_BATON_KEY_GEN`, `CKM_CAMELLIA_CTR`, and `CKM_DES_CBC`, proving zero flags
are written into caller-owned `CK_MECHANISM_INFO` stack structs without
provider support. The semantic MockBackend constructor also has an exhaustive
backend test that selects every official mechanism with zero source-grounded
workflow flags and verifies each mechanism-bearing workflow rejects it with
`CKR_MECHANISM_INVALID`.

The mechanism matrix therefore separates broad MockBackend catalog smoke from
source-grounded workflow semantics. `catalog_smoke_workflows` shows that an
advertised official `CKM_*` value can traverse generic simulator paths without
`CKR_MECHANISM_INVALID`. `source_grounded_workflows` is populated only when the
OASIS source evidence also supports mechanism-specific workflow flags. For
rows such as `CKM_BATON_KEY_GEN`, the catalog smoke remains useful but the
semantic status stays `no_source_workflow_evidence`.

## Profile Area Coverage

### Core Functions (OASIS §5.1–5.7)

| Area | Functions | Coverage Level | Test Location |
|------|-----------|---------------|---------------|
| General | C_Initialize, C_Finalize, C_GetInfo, C_GetFunctionList | Full (including C_Initialize/C_Finalize reserved-pointer validation) | shim ABI tests, integration tests |
| Interface | C_GetInterfaceList, C_GetInterface | Full (2.40, 3.0, 3.2) | shim interface catalog tests |
| Slot/Token | C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, C_GetMechanismInfo, C_WaitForSlotEvent | Represented (including C ABI reserved-pointer validation, MockBackend blocking/nonblocking slot-event queue semantics, finalize/init slot-event lifecycle cleanup, and loaded-shim nonblocking lifecycle dispatch) | integration tests, provider matrix, MockBackend tests |
| Session | C_OpenSession, C_CloseSession, C_CloseAllSessions, C_GetSessionInfo | Full | integration tests, concurrency tests |
| Login/Auth | C_Login, C_Logout, C_InitToken, C_InitPIN, C_SetPIN | Full | integration tests, auth matrix |
| Random | C_SeedRandom, C_GenerateRandom | Full | unit tests, integration tests |
| Object Mgmt | C_CreateObject, C_DestroyObject, C_CopyObject, C_GetObjectSize, C_GetAttributeValue, C_SetAttributeValue, C_FindObjects* | Full (exact output + MockBackend active search state for C_FindObjects*) | object management tests, provider matrix, output_semantics tests. C_GetAttributeValue uses exact/raw path with nested `CKF_ARRAY_ATTRIBUTE` support. |

### Cryptographic Operations (OASIS §5.8–5.14)

| Area | Functions | Coverage Level | Test Location |
|------|-----------|---------------|---------------|
| Encrypt | C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinal | Full (exact output + MockBackend gRPC `mechanism_out` for init-time and late AES-GCM output across one-shot, exact-output, and multipart paths) | integration tests, MockBackend gRPC tests, pkcs11test, output_semantics tests |
| Decrypt | C_DecryptInit, C_Decrypt, C_DecryptUpdate, C_DecryptFinal | Full (exact output) | integration tests, pkcs11test, output_semantics tests |
| Digest | C_DigestInit, C_Digest, C_DigestUpdate, C_DigestKey, C_DigestFinal | Full (exact output) | integration tests, pkcs11test, output_semantics tests |
| Sign | C_SignInit, C_Sign, C_SignUpdate, C_SignFinal | Full (exact output) | integration tests, pkcs11test, consumer tests, output_semantics tests |
| Verify | C_VerifyInit, C_Verify, C_VerifyUpdate, C_VerifyFinal | Full | integration tests, pkcs11test |
| Sign/Verify Recover | C_SignRecoverInit, C_SignRecover, C_VerifyRecoverInit, C_VerifyRecover | Full (exact output) | NSS integration test, output_semantics tests |
| Key Gen | C_GenerateKey, C_GenerateKeyPair | Full | integration tests, provider matrix |
| Key Wrap | C_WrapKey, C_UnwrapKey | Full (exact output + mechanism_out for WrapKey since 2026-05-15) | integration tests, output_semantics tests |
| Key Derive | C_DeriveKey | Full (exact output + `mechanism_out` since 2026-05-15 — covers TLS12/WTLS master-key-derive `pVersion`, SSL3/TLS/WTLS key-material handles/IV, PBE IV, SP800-108 Counter/Feedback/Double Pipeline success-path additional-key handle writeback, SP800-108 template-failure `CK_DERIVED_KEY.phKey = CK_INVALID_HANDLE` writeback on non-`CKR_OK`, SP800-108 key-handle data-param validation, SP800-108 PRF-type validation, SP800-108 mode data-param validation, and SP800-108 data-param payload/singleton validation including DKM length method values and non-empty `CK_SP800_108_BYTE_ARRAY`) | integration tests, MockBackend gRPC tests, shim writeback tests, local inventory tests |

### Combined Operations (OASIS §5.15)

| Area | Functions | Coverage Level | Test Location |
|------|-----------|---------------|---------------|
| Combined | C_DigestEncryptUpdate, C_DecryptDigestUpdate, C_SignEncryptUpdate, C_DecryptVerifyUpdate | Full (exact output) | combined operation tests, output_semantics tests |

### State Management (OASIS §5.16)

| Area | Functions | Coverage Level | Test Location |
|------|-----------|---------------|---------------|
| Operation State | C_GetOperationState, C_SetOperationState | Full (exact output for Get) | state management tests, output_semantics tests |

### PKCS#11 3.0 Extensions (OASIS §5.17+)

| Area | Functions | Coverage Level | Notes |
|------|-----------|---------------|-------|
| C_LoginUser | Full proxy path; deterministic MockBackend coverage | Internal | 3.0 interface, proxied when backend supports it |
| C_SessionCancel | Full proxy path; deterministic MockBackend coverage | Internal | Cancels and clears session-scoped simulator state |
| Message-based Encrypt/Decrypt/Sign | C_EncryptMessage*, C_DecryptMessage*, C_SignMessage* | Full (exact output) | output_semantics tests. Uses ParameterOutputExact RPC with dual output (ciphertext + parameter write-back). |
| Message-based Verify | C_VerifyMessage* | Full | Proxied, no output buffer semantics (verify returns only CK_RV). |

### PKCS#11 3.2 Extensions

| Area | Functions | Coverage Level | Notes |
|------|-----------|---------------|-------|
| KEM | C_EncapsulateKey | Full (exact output) | output_semantics tests. Uses EncapsulateKeyExact RPC (ciphertext + key handle). Mock supports size-query, data-query, buffer-too-small. |
| KEM | C_DecapsulateKey | Full | Proxied, no output buffer semantics (returns key handle only). |
| Authenticated Wrap | C_WrapKeyAuthenticated | Full (exact output) | output_semantics tests. Uses ParameterOutputExact RPC. |
| Authenticated Wrap | C_UnwrapKeyAuthenticated | Full | Proxied, no output buffer semantics (returns key handle). |
| Async | C_AsyncComplete, C_AsyncGetID, C_AsyncJoin | Full proxy path; deterministic MockBackend coverage | 3.2 interface; provider behavior depends on backend support |
| Validation | C_GetSessionValidationFlags | Full proxy path; deterministic MockBackend coverage | 3.2 interface; provider behavior depends on backend support |
| Signature Verify | C_VerifySignatureInit, C_VerifySignature, C_VerifySignatureUpdate, C_VerifySignatureFinal | Full | 3.2 interface, proxied. No output buffer semantics. |

## Mechanism Coverage

### Modeled Mechanisms And MockBackend Inventory

Mechanism parameter modeling is maintained in:

- `crates/types/src/mechanism.rs` (`CkMechanismParams`, currently 79 variants);
- `crates/proto/src/convert/message_params.rs` (three message-operation
  parameter shapes);
- `proto/pkcs11-proxy-ng/v1/mechanism_params.proto`;
- `proto/pkcs11-proxy-ng/v1/types.proto`;
- `crates/proto/src/convert/mechanism/*`;
- `crates/types/src/mechanism_params_default.toml`;
- `crates/types/src/mechanism_official.rs` (463 official v3.2 mechanism values,
  checked against the vendored OASIS published headers).

`MockBackend::with_default_mechanism_registry()` advertises every mechanism from
the embedded mechanism registry.
`MockBackend::with_official_mechanism_catalog_smoke()` advertises the generated
463-entry official mechanism catalog, including mechanisms that no current
provider artifact exposes, and keeps broad synthetic protocol coverage
available for every published `CKM_*` value.
`MockBackend::with_official_mechanisms()` advertises the same official catalog
but rejects mechanism-bearing operations unless the requested workflow is
backed by the mechanism's source-grounded `CK_MECHANISM_INFO` flags. The
simulator returns synthetic, semantically shaped outputs; it does not claim
cryptographic correctness.

Working-spec mechanism names without published numeric values remain visible in
the generated inventory but are not advertised by `MockBackend` until a
published header value exists locally.

Each generated mechanism-matrix row includes the published `CKM_*` value,
aliases, version introduced, workflow columns, parameter structs, internal
MockBackend catalog-smoke evidence, source-grounded MockBackend workflow
evidence, the semantic MockBackend constructor, the workflow-enforcement test,
exact-output simulator coverage evidence, provider artifact status, provider
gap status, any explicit unsupported reason, and any source-discrepancy reason.
The mechanism-row parameter struct list is source-local: it is populated only
from nearby mechanism prose such as "provides the parameters to `CKM_*`" or
explicit "has a parameter" statements, not from every `CK_*PARAMS` token in the
same spec file. The separate parameter-shape matrix remains the full
row-per-struct Rust/proto/FFI/shim coverage inventory.

Provider-backed tests remain required for real cryptographic/provider behavior.
The generated inventory marks provider gaps using `../pkcs11-check` artifacts
but does not treat provider coverage as sufficient internal coverage. The
current generated matrix distinguishes 463 unique published mechanism values
from 479 official mechanism names/aliases. Provider artifacts cover 315 of
those names/aliases and leave 164 names/aliases as provider gaps. Internal
MockBackend coverage is reported separately from provider artifacts and cites
the backend tests that advertise every official mechanism, run every official
mechanism through the simulator's catalog-smoke workflows, and exercise exact
size-query/data-query paths for byte-output, handle-output, and
parameter-output workflows. The same matrix carries
`workflow_semantics_status`, `semantic_constructor`,
`source_grounded_workflow_enforcement_test`, `semantic_limitation`, and
`source_grounded_workflows` so those broad smoke tests are not mistaken for
OASIS-backed mechanism-specific semantics. It also cites negative
catalog-semantics tests that reject unadvertised mechanisms and source-unsupported
workflows on mechanism-bearing paths, so the all-official simulator catalog is
both broad and explicit about semantic limits.

### Parameterless Mechanisms (transparent proxy)

CKM_RSA_PKCS, CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_SHA256, CKM_AES_KEY_GEN, CKM_EC_KEY_PAIR_GEN, and all others without params.

## Exact Output Semantics (2026-04-04)

The shim uses exact/raw output semantics for all output-bearing PKCS#11
functions. The design requirement is **behavioral fidelity**: an application
loading the shim `.so` must not be able to distinguish it from loading the
real backend `.so` directly, except for network latency.

### How It Works

1. The shim sends the caller's exact buffer specification (NULL vs provided,
   exact length) to the daemon via a dedicated gRPC RPC.
2. The daemon passes the specification to the backend, which performs
   **exactly one** PKCS#11 FFI call with those parameters.
3. The shim writes back the exact result — `CK_RV`, returned length, and
   bytes (when present) — without local reconstruction.

### RPCs

| RPC | Output Shape | Functions |
|-----|-------------|-----------|
| `GetAttributeValueExact` | Per-attribute results | C_GetAttributeValue (with nested CKF_ARRAY_ATTRIBUTE) |
| `ByteOutputExact` | CK_RV + length + bytes | 18 byte-output functions (sign, encrypt, digest, etc.) |
| `ParameterOutputExact` | Output bytes + parameter write-back | 7 message-crypto + auth-wrap functions |
| `EncapsulateKeyExact` | Ciphertext + key handle | C_EncapsulateKey |

### What Changed

Previously, the shim used `two_call_cached_bytes` to call the backend once,
cache the full result, and then locally reconstruct `CKR_BUFFER_TOO_SMALL`
and size-query responses. This was incorrect for:
- Stateful update functions (consumed backend state before checking caller buffer)
- Per-attribute results in `C_GetAttributeValue` (fabricated zero-filled values)
- Combined operations (undefined behavior on buffer-too-small)

These issues are now resolved. The old cache helpers have been deleted.

## External Conformance Tools

| Tool | Integration | Coverage |
|------|------------|---------|
| Google pkcs11test | Curated filter subset | Session, object, crypto, digest operations |
| OpenSC pkcs11-tool --test | Built-in test suite | Slot/token info, crypto smoke |
| GnuTLS p11tool | Token listing, object enumeration | URI-driven access |
| OpenSSL pkcs11prov | CSR generation via PKCS#11 provider | Provider-based crypto workflow |

## Provider Validation Matrix

| Provider | Status | Mechanism Set |
|----------|--------|--------------|
| SoftHSM2 | Primary integration target | RSA, AES, SHA, EC |
| NSS softokn | Secondary target | RSA, SHA, sign-recover |
| Kryoptic | Experimental | RSA, AES, SHA, EC |

## Notes

- "Full" coverage means the function is implemented across all layers with tests
- "ABI-complete" means the function has a non-null stub returning CKR_FUNCTION_NOT_SUPPORTED
- "Partial" means implementation exists but validation is limited to specific backends
- Profile coverage is additive — new backends and test modes expand validated claims

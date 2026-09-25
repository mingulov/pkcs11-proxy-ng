# PKCS#11 coverage

This reference describes the interfaces and parameter shapes represented by
the proxy. The inventory and profile tables are a **2026-05-17 snapshot**;
the FFI reader limits were updated on 2026-09-22. For release support and
current validation limits, see the [support matrix](release/beta-support-matrix.md)
and [candidate notes](release/v0.2.0-release-notes.md).

## Generating the inventory

[scripts/oasis-coverage-inventory.py](../scripts/oasis-coverage-inventory.py)
compares OASIS sources with the function tables, protobuf messages, Rust types,
FFI conversions, shim dispatch, and test references.

Supply an external OASIS checkout containing `working/doc/spec/` and the
published headers:

```bash
PKCS11_PROXY_NG_OASIS_ROOT=/path/to/oasis-tcs-pkcs11 \
    python3 scripts/oasis-coverage-inventory.py --format markdown
```

The script can also read local coverage artifacts from
[pkcs11-check](https://github.com/mingulov/pkcs11-check). Mock coverage and
provider results are reported separately. Neither a test citation nor a zero
gap count establishes release qualification.

Working specification text, published headers, and `cryptoki-sys` bindings
can disagree. The inventory records those differences explicitly. Published
headers supply ABI layouts and numeric mechanism values; the project does not
invent missing values or extend standard function-list layouts.

## Inventory snapshot

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


## Interfaces and intentional omissions

The shim exposes standard `PKCS 11` interface catalogs for 2.40, 3.0, and 3.2.
`C_GetFunctionList`, `C_GetInterfaceList`, and `C_GetInterface` are local
shim entry points and do not need RPCs. Loaded-shim tests check catalog order
and version selection.

The six `C_DigestXof*` functions appear in working specification text but
have no fields in the published function lists or the `cryptoki-sys` layouts
used here. They remain explicit gaps; the shim adds neither private exports
nor custom function-list fields.

`MockBackend` inherits `CKR_FUNCTION_NOT_PARALLEL` defaults for
`C_GetFunctionStatus` and `C_CancelFunction`. It does not simulate legacy
parallel execution.

The following are intentional omissions from the default mechanism registry
under [the contributor rules](../AGENTS.md#12-mechanism-parameter-rules):

- Working-spec names without published numeric values:
  `CKM_KMAC128`, `CKM_KMAC256`, `CKM_ML_DSA_EXTERNAL_MU`,
  `CKM_ML_DSA_EXTERNAL_MU_GEN`, `CKM_SHAKE_128`, and `CKM_SHAKE_256`.
  They receive no project-local mechanism numbers.
- `CK_CMS_SIG_PARAMS`, `CK_X3DH_*`, and `CK_X2RATCHET_*` parameter
  shapes whose caller pointers have no usable length bounds. Their typed
  transport/FFI representations do not make a generic C pointer read safe.
  Direct parameterized shim calls are rejected with
  `CKR_MECHANISM_PARAM_INVALID`.
- Raw and vendor transport-only variants without a safe backend ABI mapping.
  Backend conversion rejects these with `CKR_MECHANISM_PARAM_INVALID`.

The inventory also distinguishes aliases and placeholders from missing types:

- `CK_ECMQV_DERIVE_PARAMS` has a published mechanism mapping.
  `CK_ECDH2_DERIVE_PARAMS` remains a helper/transport shape because there is
  no separate published `CKM_ECDH2_DERIVE` value.
- Working prose uses `CK_CHACHA20POLY1305_PARAMS` for the published
  `CK_SALSA20_CHACHA20_POLY1305_PARAMS` layout.
- `CK_XXX_MESSAGE_PARAMS` is a placeholder for mechanism-specific message
  parameters, not a concrete C type.

## What the tests cover

The generated matrices trace each function and parameter shape through the
applicable shim, client, protobuf, backend, and FFI layers. Test references
cover conversions, loaded C ABI calls, exact output behavior, and modeled
provider operations. Missing or stale test citations are reported explicitly.

Message parameters are separate from `CK_MECHANISM` parameters. The modeled
GCM, CCM, and Salsa/ChaCha message shapes apply to Encrypt/Decrypt. Encrypt
can write parameters back; Decrypt is input-only. Sign/Verify accept empty
parameters only. An unmodeled non-NULL, nonempty parameter is rejected.

The tables below describe the recorded test coverage. **Full** means the
function had an implementation and tests across its applicable layers; it
does not mean exhaustive provider validation. Later support restrictions,
including nonblocking-only native slot waits, are in the
[candidate notes](release/v0.2.0-release-notes.md#current-limits).

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

## Mechanism coverage

Parameter definitions and conversions live in:

- `crates/types/src/mechanism.rs` and `mechanism_params_default.toml`;
- `proto/pkcs11-proxy-ng/v1/mechanism_params.proto` and `types.proto`;
- `crates/proto/src/convert/mechanism/` and `message_params.rs`;
- `crates/backend/src/ffi/ffi_conversion/`.

The official numeric catalog is generated in
`crates/types/src/mechanism_official.rs`. Mechanisms without parameters,
such as `CKM_RSA_PKCS`, `CKM_SHA256`, and `CKM_AES_KEY_GEN`, need no
parameter layout.

### MockBackend

| Constructor | Purpose |
| --- | --- |
| `with_default_mechanism_registry()` | Advertise the embedded registry. |
| `with_official_mechanism_catalog_smoke()` | Exercise generic transport paths for every published mechanism value. |
| `with_official_mechanisms()` | Advertise the same catalog, but allow operations only where OASIS sources provide workflow flags. |

Mock output is synthetic. Real providers are required to test cryptographic
behavior.

Mechanisms with published values remain in the catalog even when working
Markdown omits them. If sources do not establish workflow flags, the semantic
mock reports zero flags and rejects mechanism-bearing operations with
`CKR_MECHANISM_INVALID`. It does not infer flags from mechanism names.

The inventory keeps catalog smoke, source-based workflow tests, parameter
coverage, and provider evidence separate. Its `completion_gap_summary`
groups missing test citations, intentional omissions, and remaining gaps;
the underlying rows contain the reasons and evidence.

### FFI reader limits

- **Nesting:** at most 16 nested mechanism nodes. A 17th node or a cycle in
  active caller addresses is rejected before recursion.
- **Copy sizes:** parameter structs and raw fallback copies are limited to
  65,536 bytes (`MAX_MECHANISM_PARAM_STRUCT_LEN`). Embedded data such as AAD
  and IVs is limited to 512 MiB (`MAX_SERIALIZABLE_BYTES`).
- **Address arithmetic:** readers check count, multiplication, size, and
  end-address overflow before constructing a slice. These checks cannot prove
  that memory is mapped or readable. Embedded pointers remain subject to the
  caller's FFI contract; `ulParameterLen` does not bound their allocations.
- **Alignment:** readers use unaligned copies and do not form aligned
  references into caller memory.

Inputs over these limits return `CKR_MECHANISM_PARAM_INVALID` in shim
readers and backend typed conversion.

## Exact output semantics

For output-bearing calls, the shim sends the caller's buffer presence and
capacity to the daemon. The backend makes one native PKCS#11 call; the shim
returns its `CK_RV`, lengths, and bytes. It does not simulate size queries
or reconstruct `CKR_BUFFER_TOO_SMALL` from cached output.

| RPC | Output Shape | Functions |
|-----|-------------|-----------|
| `GetAttributeValueExact` | Per-attribute results | C_GetAttributeValue (with nested CKF_ARRAY_ATTRIBUTE) |
| `ByteOutputExact` | CK_RV + length + bytes | 18 byte-output functions (sign, encrypt, digest, etc.) |
| `ParameterOutputExact` | Output bytes + parameter write-back | 7 message-crypto + auth-wrap functions |
| `EncapsulateKeyExact` | Ciphertext + key handle | C_EncapsulateKey |


## External test tools

| Tool | Integration | Coverage |
|------|------------|---------|
| Google pkcs11test | Curated filter subset | Session, object, crypto, digest operations |
| OpenSC pkcs11-tool --test | Built-in test suite | Slot/token info, crypto smoke |
| GnuTLS p11tool | Token listing, object enumeration | URI-driven access |
| OpenSSL pkcs11prov | CSR generation via PKCS#11 provider | Provider-based crypto workflow |


Provider testing instructions are in the [test guide](../crates/server/tests/README.md).
The [March provider tables](provider-support-tables.md) are historical.

# OASIS PKCS#11 Profile Coverage Mapping

**Date:** 2026-04-04 (updated for exact output-semantics migration)

## Purpose

Maps OASIS PKCS#11 specification profile areas to this project's validation
coverage. This is a living document updated as test coverage expands.

## Profile Area Coverage

### Core Functions (OASIS §5.1–5.7)

| Area | Functions | Coverage Level | Test Location |
|------|-----------|---------------|---------------|
| General | C_Initialize, C_Finalize, C_GetInfo, C_GetFunctionList | Full | shim ABI tests, integration tests |
| Interface | C_GetInterfaceList, C_GetInterface | Full (2.40, 3.0, 3.2) | shim interface catalog tests |
| Slot/Token | C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, C_GetMechanismInfo | Full | integration tests, provider matrix |
| Session | C_OpenSession, C_CloseSession, C_CloseAllSessions, C_GetSessionInfo | Full | integration tests, concurrency tests |
| Login/Auth | C_Login, C_Logout, C_InitToken, C_InitPIN, C_SetPIN | Full | integration tests, auth matrix |
| Random | C_SeedRandom, C_GenerateRandom | Full | unit tests, integration tests |
| Object Mgmt | C_CreateObject, C_DestroyObject, C_CopyObject, C_GetObjectSize, C_GetAttributeValue, C_SetAttributeValue, C_FindObjects* | Full (exact output) | object management tests, provider matrix, output_semantics tests. C_GetAttributeValue uses exact/raw path with nested `CKF_ARRAY_ATTRIBUTE` support. |

### Cryptographic Operations (OASIS §5.8–5.14)

| Area | Functions | Coverage Level | Test Location |
|------|-----------|---------------|---------------|
| Encrypt | C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinal | Full (exact output) | integration tests, pkcs11test, output_semantics tests |
| Decrypt | C_DecryptInit, C_Decrypt, C_DecryptUpdate, C_DecryptFinal | Full (exact output) | integration tests, pkcs11test, output_semantics tests |
| Digest | C_DigestInit, C_Digest, C_DigestUpdate, C_DigestKey, C_DigestFinal | Full (exact output) | integration tests, pkcs11test, output_semantics tests |
| Sign | C_SignInit, C_Sign, C_SignUpdate, C_SignFinal | Full (exact output) | integration tests, pkcs11test, consumer tests, output_semantics tests |
| Verify | C_VerifyInit, C_Verify, C_VerifyUpdate, C_VerifyFinal | Full | integration tests, pkcs11test |
| Sign/Verify Recover | C_SignRecoverInit, C_SignRecover, C_VerifyRecoverInit, C_VerifyRecover | Full (exact output) | NSS integration test, output_semantics tests |
| Key Gen | C_GenerateKey, C_GenerateKeyPair | Full | integration tests, provider matrix |
| Key Wrap | C_WrapKey, C_UnwrapKey | Full (exact output for WrapKey) | integration tests, output_semantics tests |
| Key Derive | C_DeriveKey | Full | integration tests |

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
| C_LoginUser | Stub (CKR_FUNCTION_NOT_SUPPORTED) | ABI-complete | 3.0 interface, not proxied |
| C_SessionCancel | Stub (CKR_FUNCTION_NOT_SUPPORTED) | ABI-complete | 3.0 interface, not proxied |
| Message-based Encrypt/Decrypt/Sign | C_EncryptMessage*, C_DecryptMessage*, C_SignMessage* | Full (exact output) | output_semantics tests. Uses ParameterOutputExact RPC with dual output (ciphertext + parameter write-back). |
| Message-based Verify | C_VerifyMessage* | Full | Proxied, no output buffer semantics (verify returns only CK_RV). |

### PKCS#11 3.2 Extensions

| Area | Functions | Coverage Level | Notes |
|------|-----------|---------------|-------|
| KEM | C_EncapsulateKey | Full (exact output) | output_semantics tests. Uses EncapsulateKeyExact RPC (ciphertext + key handle). Mock supports size-query, data-query, buffer-too-small. |
| KEM | C_DecapsulateKey | Full | Proxied, no output buffer semantics (returns key handle only). |
| Authenticated Wrap | C_WrapKeyAuthenticated | Full (exact output) | output_semantics tests. Uses ParameterOutputExact RPC. |
| Authenticated Wrap | C_UnwrapKeyAuthenticated | Full | Proxied, no output buffer semantics (returns key handle). |
| Async | C_AsyncComplete, C_AsyncGetID, C_AsyncJoin | Stub | 3.2 interface, not proxied |
| Validation | C_GetSessionValidationFlags | Stub | 3.2 interface, not proxied |
| Signature Verify | C_VerifySignatureInit, C_VerifySignature, C_VerifySignatureUpdate | Full | 3.2 interface, proxied. No output buffer semantics. |

## Mechanism Coverage

### Modeled Mechanisms (full parameter support)

| Mechanism | Param Type | Validated Against |
|-----------|-----------|-------------------|
| CKM_RSA_PKCS_PSS | RsaPkcsPssParams | SoftHSM2 |
| CKM_RSA_PKCS_OAEP | RsaPkcsOaepParams | SoftHSM2 |
| CKM_AES_GCM | GcmParams | SoftHSM2 |
| CKM_ECDH1_DERIVE | Ecdh1DeriveParams | SoftHSM2 |
| CKM_AES_CBC | IvParams | SoftHSM2 |
| CKM_AES_CBC_PAD | IvParams | SoftHSM2 |
| CKM_DES3_CBC | IvParams | SoftHSM2 |
| CKM_DES3_CBC_PAD | IvParams | SoftHSM2 |

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

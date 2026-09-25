# Per-Provider Support Tables

Last updated: 2026-03-13

This document distinguishes three levels of support for each PKCS#11 operation:

- **Backend** — the provider module reports the mechanism or operation
- **Proxy** — the proxy models, forwards, and handles the operation
- **Validated** — an automated test exercises the full path through the proxy

Legend: Y = yes | N = no | P = partial | — = not applicable | ? = unknown

## SoftHSM2 (primary)

| Operation | Backend | Proxy | Validated | Notes |
|-----------|---------|-------|-----------|-------|
| C_Initialize / C_Finalize | Y | Y | Y | |
| C_GetInfo | Y | Y | Y | |
| C_GetSlotList / C_GetSlotInfo | Y | Y | Y | Multi-slot tested |
| C_GetTokenInfo | Y | Y | Y | |
| C_GetMechanismList / Info | Y | Y | Y | |
| C_OpenSession / C_CloseSession | Y | Y | Y | RO + RW |
| C_Login / C_Logout | Y | Y | Y | USER + SO |
| C_InitToken / C_InitPIN / C_SetPIN | Y | Y | Y | |
| C_GenerateKeyPair (RSA) | Y | Y | Y | Minimal + full templates |
| C_GenerateKeyPair (EC) | Y | Y | Y | P-256, P-384 |
| C_GenerateKey (AES) | Y | Y | Y | 128, 256 bit |
| C_Sign / C_Verify (RSA-PKCS) | Y | Y | Y | |
| C_SignRecover / C_VerifyRecover | N | Y | N | SoftHSM2 does not report CKF_SIGN_RECOVER |
| C_Encrypt / C_Decrypt (RSA-PKCS) | Y | Y | Y | |
| C_Encrypt / C_Decrypt (AES-GCM) | Y | Y | P | Proxy models GCM params |
| C_Digest (SHA-256) | Y | Y | Y | Two-call cache limitation with pkcs11-tool |
| C_DigestUpdate / C_DigestFinal | Y | Y | Y | |
| C_WrapKey / C_UnwrapKey | Y | Y | Y | |
| C_DeriveKey | Y | Y | Y | |
| C_CreateObject (data) | Y | Y | Y | Minimal + full templates |
| C_DestroyObject | Y | Y | Y | |
| C_CopyObject | Y | Y | Y | |
| C_GetObjectSize | Y | Y | Y | |
| C_FindObjects | Y | Y | Y | By label, by ID |
| C_GetAttributeValue | Y | Y | Y | Including partial results |
| C_SetAttributeValue | Y | Y | Y | |
| C_GenerateRandom | Y | Y | Y | |
| C_SeedRandom | Y | Y | Y | |
| C_GetOperationState | P | Y | P | May return CKR_STATE_UNSAVEABLE |
| C_SetOperationState | P | Y | P | |
| C_WaitForSlotEvent | Y | Y | Y | Blocking + non-blocking |
| C_SignEncryptUpdate | Y | Y | Y | Combined operation |
| C_DecryptVerifyUpdate | Y | Y | Y | Combined operation |
| C_DigestEncryptUpdate | Y | Y | Y | Combined operation |
| C_DecryptDigestUpdate | Y | Y | Y | Combined operation |

### SoftHSM2 Skip/Xfail Summary

| Test area | Status | Reason |
|-----------|--------|--------|
| Sign/verify recover | Skip | No CKF_SIGN_RECOVER/CKF_VERIFY_RECOVER flags |
| Fork test | Xfail | Tokio runtime does not survive fork() |
| Hotplug | Skip | Software token, no physical events |
| Digest two-call (pkcs11-tool) | Xfail | Shim cache consumes backend op state |

## NSS softokn (optional)

| Operation | Backend | Proxy | Validated | Notes |
|-----------|---------|-------|-----------|-------|
| C_Initialize / C_Finalize | Y | Y | Y | Requires configDir |
| C_GetInfo | Y | Y | Y | |
| C_GetSlotList / C_GetSlotInfo | Y | Y | Y | |
| C_GetTokenInfo | Y | Y | Y | |
| C_GetMechanismList / Info | Y | Y | Y | |
| C_OpenSession / C_CloseSession | Y | Y | Y | |
| C_Login / C_Logout | Y | Y | Y | |
| C_GenerateKeyPair (RSA) | Y | Y | Y | |
| C_Sign / C_Verify (RSA-PKCS) | Y | Y | Y | |
| C_SignRecover / C_VerifyRecover | Y | Y | Y | NSS reports CKF_SIGN_RECOVER |
| C_Encrypt / C_Decrypt (RSA-PKCS) | Y | Y | Y | |
| C_Digest (SHA-256) | Y | Y | Y | |
| C_GenerateRandom | Y | Y | Y | |
| C_FindObjects | Y | Y | Y | |

### NSS softokn Skip/Xfail Summary

| Test area | Status | Reason |
|-----------|--------|--------|
| AES keygen | Skip | May not be available in all NSS builds |
| RSA-OAEP | Skip | Behavior varies by NSS version |
| Fork test | Xfail | Tokio runtime does not survive fork() |

## Kryoptic (experimental)

| Operation | Backend | Proxy | Validated | Notes |
|-----------|---------|-------|-----------|-------|
| C_Initialize / C_Finalize | Y | Y | ? | Env-driven, no CI |
| C_GetInfo | Y | Y | ? | |
| C_GetSlotList / C_GetSlotInfo | Y | Y | ? | |
| C_GetTokenInfo | Y | Y | ? | |
| C_GetMechanismList / Info | Y | Y | ? | |
| C_GenerateKeyPair (RSA) | Y | Y | ? | |
| C_Sign / C_Verify | Y | Y | ? | |
| C_Digest | Y | Y | ? | |
| C_GenerateRandom | Y | Y | ? | |

### Kryoptic Skip/Xfail Summary

| Test area | Status | Reason |
|-----------|--------|--------|
| All tests | Skip | Requires PKCS11_PROXY_KRYOPTIC_MODULE env var |
| Fork test | Xfail | Tokio runtime does not survive fork() |

## Cross-Provider Notes

1. **Fork safety**: No provider works with fork() due to the tokio async
   runtime limitation. This is fundamental, not provider-specific.

2. **Digest two-call cache**: The shim's `two_call_cached_bytes` pattern
   affects all providers equally. It consumes the server-side operation
   during the size query.

3. **Template defaults**: CKA_TOKEN defaults to session object across all
   tested providers when omitted.

4. **OS locking**: CKF_OS_LOCKING_OK is accepted by the shim for all
   providers (per ADR decision).

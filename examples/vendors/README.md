# Vendor Mechanism Override Examples

These TOML files configure the proxy to support vendor-specific PKCS#11
mechanisms from various HSM manufacturers.

## Usage

Set the environment variable to load a vendor override:
    PKCS11_PROXY_MECHANISMS=/path/to/vendor-file.toml

The override is additive — it merges on top of the embedded default
configuration. Only add the vendor mechanisms you need.

## Available vendor configs

| File | Vendor | Key mechanisms |
|------|--------|---------------|
| aws-cloudhsm.toml | AWS CloudHSM | AES-GCM (HSM-generated IV), key wraps, SP800-108 KDF |
| thales-luna.toml | Thales Luna Network HSM | Korean crypto (SEED/KCDSA/ARIA), EdDSA, ECIES, payment DUKPT |
| entrust-nshield.toml | Entrust nShield | AES-CMAC, ECIES, HMAC key gen |
| ibm-ep11.toml | IBM EP11 / HPCS | SHA-3, EdDSA, Dilithium, Kyber, BTC/ETH derive |
| yubico-yubihsm.toml | Yubico YubiHSM 2 | AES-CCM wrap |
| google-cloudkms.toml | Google Cloud KMS | AES-GCM (HSM-generated IV) |
| mozilla-nss.toml | Mozilla NSS | HKDF, AES key wrap, PBE, TLS PRF |
| russian-gost.toml | GOST / TC26 | GOST R 34.10/34.11-2012 |

## Notes

- Hex values are approximate for some vendors (nShield, Yubico).
  Run C_GetMechanismList on your actual HSM to verify exact values.
- nShield uses a non-standard vendor base (0xDE436972), not 0x80000000.
- Multiple override files cannot be loaded simultaneously. Combine
  entries into a single file if you need mechanisms from multiple vendors.

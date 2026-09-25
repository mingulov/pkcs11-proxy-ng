# Vendor Mechanism Override Examples

These TOML files provide example parameter definitions for vendor mechanisms.
Check mechanism numbers and parameter layouts against your provider before
using them.

## Usage

Set the daemon's `[mechanisms].config_path` to an override file so it can
publish the registry to shims. For a local shim fallback, set:

```bash
export PKCS11_PROXY_MECHANISMS=/path/to/vendor-file.toml
```

Overrides merge with the embedded defaults. Add only mechanisms your provider
supports. Restart clients after updating the daemon's registry.

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
- Load one override file at a time. Combine entries if you need mechanisms
  from multiple vendors.

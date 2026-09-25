# PKCS#11 Consumer Compatibility Matrix

Fixture for the SRE/Compat consumer matrix. Runs every supported
consumer toolchain through the shim against every supported backend.

## Layout

```
tests/consumers/
├── README.md                          ← this file
├── docker-compose.yml                 ← all backends + consumers
├── Dockerfile.daemon.softhsm2         ← SoftHSM2 stock backend
├── Dockerfile.daemon.softhsm2-patched ← SoftHSM2 + CloudHSM mech patch
├── Dockerfile.daemon.nss              ← NSS softokn3 backend
├── Dockerfile.daemon.p11kit           ← p11-kit-proxy meta-backend
├── Dockerfile.daemon.kryoptic         ← Kryoptic (Rust) backend
├── Dockerfile.consumer.shell          ← pkcs11-tool, p11tool, OpenSSL engine + provider
├── Dockerfile.consumer.go             ← miekg/pkcs11 + ThalesGroup/crypto11
├── Dockerfile.consumer.java           ← OpenJDK SunPKCS11
├── scripts/                           ← per-consumer test scripts
├── harnesses/                         ← Go and Java test harnesses
├── backends/softhsm2-patched/         ← patch for CKM_CLOUDHSM_AES_GCM
└── run_matrix.sh                      ← iterate the matrix, write results.txt
```

## Quick start

```bash
docker compose -f tests/consumers/docker-compose.yml build
tests/consumers/run_matrix.sh
cat tests/consumers/results.txt
```

The matrix runs each consumer × backend cell sequentially (consumers
share container instances; the daemon changes per backend). Results
go to `results.txt` as `consumer/backend: PASS|FAIL <notes>`.

## Backends

| Backend | Module path in daemon image | Notes |
| --- | --- | --- |
| SoftHSM2 (stock) | /usr/lib/softhsm/libsofthsm2.so | Reference |
| SoftHSM2 (patched) | /usr/local/lib/softhsm/libsofthsm2.so | Adds CKM_CLOUDHSM_AES_GCM (0x80001087) as alias for AES-GCM. Used to verify the vendor-extension path end-to-end. |
| NSS softokn | /usr/lib/libsoftokn3.so | Different mechanism set; some ops return CKR_FUNCTION_NOT_SUPPORTED |
| p11-kit-proxy | /usr/lib/p11-kit-proxy.so | Meta-backend chaining SoftHSM2 |
| Kryoptic | /usr/lib/libkryoptic_pkcs11.so | Rust PKCS#11 token (FIPS-targeted) |

# PKCS#11 consumer tests

This Docker fixture runs the listed consumer tools through the shim against the
listed software backends. It records each consumer and backend result.

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

Run from the repository root. The checkout directory must be named
`pkcs11-proxy-ng`: this fixture uses its parent as the Docker build context
and prefixes Dockerfile and `COPY` paths with `pkcs11-proxy-ng/`.

Build the Alpine APK carrier image first; each fixture image installs the
proxy packages from it. Build one backend profile at a time: the mutually
exclusive daemon services share a container name.

```bash
docker build -f packaging/alpine/Dockerfile.alpine \
  -t pkcs11-proxy-ng:test-alpine3.23 .
for backend in softhsm2 softhsm2-patched nss p11kit kryoptic; do
  docker compose -f tests/consumers/docker-compose.yml --profile "$backend" build
done
tests/consumers/run_matrix.sh
cat tests/consumers/results.txt
```

The matrix runs consumer and backend combinations sequentially because the
consumers share containers and the daemon changes for each backend. It writes
`results.txt` entries as `consumer/backend: PASS|FAIL <notes>`.

## Backends

| Backend | Module path in daemon image | Notes |
| --- | --- | --- |
| SoftHSM2 (stock) | /usr/lib/softhsm/libsofthsm2.so | Reference |
| SoftHSM2 (patched) | /usr/local/lib/softhsm/libsofthsm2.so | Adds CKM_CLOUDHSM_AES_GCM (0x80001087) as alias for AES-GCM. Used to verify the vendor-extension path end-to-end. |
| NSS softokn | /usr/lib/libsoftokn3.so | Different mechanism set; some ops return CKR_FUNCTION_NOT_SUPPORTED |
| p11-kit-proxy | /usr/lib/p11-kit-proxy.so | Meta-backend chaining SoftHSM2 |
| Kryoptic | /usr/lib/libkryoptic_pkcs11.so | Rust PKCS#11 token (FIPS-targeted) |

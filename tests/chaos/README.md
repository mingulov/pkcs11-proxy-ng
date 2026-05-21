# R8 chaos test fixture

Drives the daemon into failure states that are hard to trigger
with a real PKCS#11 backend. Uses the `slow_backend.so` stub from
`tests/r2_resilience/slow_backend/` to inject delays / hangs /
errors at the FFI boundary.

## Quick start

```bash
# 1. Build the chaos daemon image (one-time):
docker build --build-arg ALPINE_VER=3.23 \
    -f packaging/alpine/Dockerfile.alpine \
    -t pkcs11-proxy-ng:test-alpine3.23 .
(cd tests/r2_resilience/slow_backend && cargo build --release)
docker build -f tests/chaos/Dockerfile.chaos-daemon \
    -t pkcs11-proxy-ng:chaos-daemon .

# 2. Bring up the fixture:
docker compose -f tests/chaos/docker-compose.yml up -d

# 3. Run a scenario:
tests/chaos/scenarios/run_scenario.sh <N>     # 1..6

# 4. Tear down:
docker compose -f tests/chaos/docker-compose.yml down -v
```

## Scenarios (6 — per R8 prompt)

| # | id | Description | Pass criteria |
| --- | --- | --- | --- |
| 1 | `backend_hang` | `SLOW_BACKEND_SIGN_DELAY_MS=120000` on C_Sign. | Shim returns CKR_DEVICE_ERROR within `request_timeout_secs`. Daemon stays alive. Future calls work once delay is dropped. |
| 2 | `backend_oom` | Stub backend variant that returns CKR_HOST_MEMORY. | Health flips NOT_SERVING after `backend_health_consecutive_failures` consecutive failures. |
| 3 | `sigstop_daemon` | SIGSTOP daemon for 60 s, then SIGCONT. | Shim's http2 keepalive trips; shim reconnects on next call (R6-9 path); client_context_id may need re-init if lease expired. |
| 4 | `disk_full_or_mid_write` | (a) chmod -w on daemon config dir + SIGHUP; (b) sed -i mid-write of mechanism_params.toml + SIGHUP. | Error logged, registry retained, daemon survives. |
| 5 | `mid_write_configmap` | Same as 4(b), called out separately for visibility. | (subsumed in 4) |
| 6 | `tls_cert_expiry` | mTLS with 60-s cert; run consumer 90 s. | Clear error returned to client post-expiry; daemon does not crash. Renewal documented in runbook. |

Each scenario is a shell script in `scenarios/`. The scripts:
- assume the fixture is already up (`docker compose ... up -d`)
- set the relevant SLOW_BACKEND_* env vars and/or signal the daemon
- drive a consumer-side probe
- print PASS/FAIL with one line of evidence

`scenarios/run_scenario.sh N` is a thin dispatcher.

## Differences from R2 resilience fixture

R2 (tests/r2_resilience/) injects faults on the NETWORK between
shim and daemon via toxiproxy. R8 (this) injects faults at the
BACKEND boundary inside the daemon. The two are complementary:
together they cover the full failure surface.

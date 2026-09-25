# Chaos tests

These scenarios test daemon behavior during backend delays, backend errors,
process pauses, configuration reload failures, and certificate expiry. They use
the test module in `tests/r2_resilience/slow_backend/` for backend faults.

## Quick start

Run from the repository root. The consumer runner uses the consumer fixture's
Docker build context, which requires the checkout directory to be named
`pkcs11-proxy-ng`.

```bash
# 1. Build the daemon image, consumer runner, and test module:
docker build --build-arg ALPINE_BUILD_IMAGE=alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0 \
    -f packaging/alpine/Dockerfile.alpine \
    -t pkcs11-proxy-ng:test-alpine3.23 .
docker compose -f tests/consumers/docker-compose.yml --profile softhsm2 build consumer-shell
(cd tests/r2_resilience/slow_backend && \
  docker run --rm -v "$PWD:/src" -w /src --entrypoint sh rust:1.94-alpine -c \
    "apk add --no-cache build-base >/dev/null && \
     RUSTFLAGS='-C target-feature=-crt-static' cargo build --release")
docker build -f tests/chaos/Dockerfile.chaos-daemon \
    -t pkcs11-proxy-ng:chaos-daemon .

# 2. Start the containers:
docker compose -f tests/chaos/docker-compose.yml up -d

# 3. Run a scenario:
tests/chaos/scenarios/run_scenario.sh <N>     # 1..6

# 4. Stop the containers:
docker compose -f tests/chaos/docker-compose.yml down -v
```

## Scenarios

| # | id | Description | Pass criteria |
| --- | --- | --- | --- |
| 1 | `backend_hang` | Delay `C_Sign` for 120 seconds. | Shim returns `CKR_FUNCTION_FAILED` before the delayed call completes; daemon survives and later calls work after the delay is removed. A timed-out native call may still complete. |
| 2 | `backend_oom` | Make backend calls return `CKR_HOST_MEMORY`. | Health becomes `NOT_SERVING` after `backend_health_consecutive_failures` consecutive failures. |
| 3 | `sigstop_daemon` | Pause the daemon with `SIGSTOP`, then resume it with `SIGCONT`. | A call during the pause fails before the RPC deadline; a later call reconnects. A client context may need reinitialization if its lease expired. |
| 4 | `disk_full_or_mid_write` | Reload after an unreadable config file, partial TOML write, or full filesystem. | Reload error is logged; the previous registry remains active; daemon survives. |
| 5 | `mid_write_configmap` | Alias for scenario 4. | Runs the same reload checks as scenario 4. |
| 6 | `tls_cert_expiry` | Use a short-lived mTLS certificate during a consumer probe. | Calls succeed before expiry and fail afterward; daemon survives. |

Each scenario script in `scenarios/` expects the containers to be running. It
sets fault variables or signals the daemon, runs a consumer probe, and prints a
result with evidence. Scenario 5 dispatches to scenario 4; `all` runs each
distinct scenario once.

`scenarios/run_scenario.sh N` is a thin dispatcher.

## Fault location

The resilience fixture in `tests/r2_resilience/` injects network faults between
shim and daemon through toxiproxy. These scenarios exercise faults in the
daemon or its backend.

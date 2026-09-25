# Reference k8s deployment for pkcs11-proxy-ng

This directory contains the manifests the SRE/ops audit
exercises. It is the recommended starting point for operators
adapting pkcs11-proxy-ng to their cluster — copy these files into
your overlay / Helm chart and tune for your environment.

## Topology

```
            ┌──────────────────────────┐
            │ Service: daemon       │
            │ sessionAffinity: ClientIP│
            └────────────┬─────────────┘
                         │
            ┌────────────┼──────────────┐
            ▼            ▼              ▼
   ┌────────────┐ ┌────────────┐ ┌────────────┐
   │ daemon-0   │ │ daemon-1   │ │ daemon-2   │
   │  + softhsm │ │  + softhsm │ │  + softhsm │
   └────────────┘ └────────────┘ └────────────┘
   (3-replica Deployment, rolling-restart safe)

   ┌────────────────────────────────────┐
   │  ConfigMap: daemon-config       │
   │    proxy.toml                      │
   │    mechanism_params.toml           │
   └────────────────────────────────────┘
```

A stub consumer `StatefulSet` runs alongside, driving the shim
against the Service hostname (`daemon.default.svc:7512`).

## Files

| File | Purpose |
| --- | --- |
| `00-namespace.yaml` | dedicated namespace `pkcs11-proxy-demo` |
| `10-configmap.yaml` | `proxy.toml` + `mechanism_params.toml` mounted into the daemon |
| `20-daemon-deployment.yaml` | 3-replica daemon `Deployment` + readiness/liveness probes |
| `30-daemon-service.yaml` | ClusterIP Service with `sessionAffinity: ClientIP` |
| `40-consumer-stub.yaml` | stub consumer `StatefulSet` that loads the shim + runs the load harness |

The Service's `sessionAffinity: ClientIP` is **load-bearing** — without
it, a shim reconnecting after a transient network failure can land
on a different daemon replica and lose its `client_context_id`. The
resilience audit documented this; the manifest enforces it.

## Quick start (with `kind`)

```bash
# 1) Build the pkcs11-proxy-ng images.
( cd ../../.. && \
  docker build --build-arg ALPINE_BUILD_IMAGE=alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0 \
    -f packaging/alpine/Dockerfile.alpine \
    -t pkcs11-proxy-ng:test-alpine3.23 . )

# 2) Build the runner image we use as the consumer-pod base.
( cd ../../../tests/r2_resilience && docker compose build )

# 3) Spin up a kind cluster and load the images.
kind create cluster --name pkcs11-proxy-demo
kind load docker-image pkcs11-proxy-ng:test-alpine3.23     --name pkcs11-proxy-demo
kind load docker-image r2_resilience-runner:latest         --name pkcs11-proxy-demo

# 4) Apply the manifests.
kubectl apply -f .

# 5) Wait for everything to come up.
kubectl -n pkcs11-proxy-demo rollout status deploy/daemon --timeout=120s

# 6) Watch the consumer's log to see the 10-rps sign loop.
kubectl -n pkcs11-proxy-demo logs -f sts/consumer-load
```

## Rolling restart under load

```bash
# In one terminal, watch the consumer's success/failure counters:
kubectl -n pkcs11-proxy-demo logs -f sts/consumer-load

# In another terminal, restart the daemon replicas:
kubectl -n pkcs11-proxy-demo rollout restart deploy/daemon

# The consumer must report zero "unrecoverable" errors. Transient
# CKR_DEVICE_ERROR / CKR_CRYPTOKI_NOT_INITIALIZED during the
# rollover are EXPECTED and counted separately; the harness retries
# such errors with a fresh C_Initialize and the SLA is "every sign
# eventually succeeds within the rollout window".
```

See [`../../doc/runbooks/operating-pkcs11-proxy-ng.md`](../../doc/runbooks/operating-pkcs11-proxy-ng.md)
for the full operator runbook.

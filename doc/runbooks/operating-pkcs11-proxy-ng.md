# Operating pkcs11-proxy-ng — Runbook

> **Reading bar.** The engineer who gets paged at 3 am should be
> able to resolve the incident using this document alone, without
> opening source code.

| Companion docs | |
| --- | --- |
| CK_RV reference | [`doc/error-reference.md`](../error-reference.md) |
| Reference k8s manifests | [`examples/k8s/`](../../examples/k8s/) |
| Example configs (dev/staging/prod) | [`examples/configs/`](../../examples/configs/) |

## 0. Prerequisites

* Kubernetes cluster ≥ 1.28 (k3s / kind / EKS / GKE / AKS / on-prem).
* A backend PKCS#11 module reachable from every daemon replica:
  * SoftHSM2 (dev/test only)
  * AWS CloudHSM client
  * Thales / SafeNet network-HSM
  * Hardware HSM mounted as a device + accessible from the pod
* `kubectl`, `helm` (optional), `jq` for log triage.
* For mTLS deployments: a CA + per-daemon and per-shim certs.

## 1. Install (first deploy)

```bash
# 1) Build / pull the carrier image.
docker pull <registry>/pkcs11-proxy-ng:<version>-alpine3.23

# 2) Apply the reference manifests (or your Helm overlay).
kubectl apply -f pkcs11-proxy-ng/examples/k8s/

# 3) Edit the ConfigMap to point at your backend module.
kubectl -n pkcs11-proxy-demo edit configmap daemon-config
# Replace [backend].module with the path inside the daemon container.

# 4) Trigger a rollout to pick up the edited config.
kubectl -n pkcs11-proxy-demo rollout restart deploy/daemon
kubectl -n pkcs11-proxy-demo rollout status deploy/daemon
```

**Smoke test.** Run a single sign through the shim from a consumer
pod (the reference manifests in `examples/k8s/` include a consumer
`StatefulSet` that drives 10-rps signing).

## 2. Upgrade (rolling, zero downtime)

```bash
# 1) Bump the image tag in the daemon Deployment.
kubectl -n <ns> set image deploy/<daemon-deploy> daemon=<registry>/pkcs11-proxy-ng:<new-version>-alpine3.23

# 2) Watch the rolling update.
kubectl -n <ns> rollout status deploy/<daemon-deploy>

# 3) Verify consumer traffic stayed clean. If you have the
#    reference consumer StatefulSet, its log shows
#    `success`/`recoverable`/`unrecoverable` counts every 20 ops.
```

**SLO.** Under the reference manifests' `sessionAffinity: ClientIP`
Service + `maxSurge: 1, maxUnavailable: 0` rollout strategy, the
SRE/ops audit observed **zero application-visible failures** through
a ~22-second rolling restart at 10 rps.

**If consumer reports unrecoverable errors during the rollout:**

1. Check pod readiness: `kubectl -n <ns> get pods -l app=<daemon-deploy>`.
2. If a new replica is `0/1 Ready` after `maxUnavailable: 0`'s tolerance,
   the rollout will pause. Investigate via `kubectl describe pod` and
   `kubectl logs`.
3. If consumer hits `Private/secret key not found` errors, the new
   replica is using its own SoftHSM2 token store instead of the
   shared one. Verify the `tokens` volume is mounted from the
   shared `hostPath` / PVC, not `emptyDir`.

## 3. Rollback

```bash
# kubectl tracks rollout history. List previous revisions:
kubectl -n <ns> rollout history deploy/<daemon-deploy>

# Roll back to the previous version:
kubectl -n <ns> rollout undo deploy/<daemon-deploy>

# Or roll to a specific revision:
kubectl -n <ns> rollout undo deploy/<daemon-deploy> --to-revision=<N>
```

**Recovery timing.** Same as upgrade — rolling-restart safe under the
reference manifests' settings. The resilience audit confirmed shim
consumers tolerate daemon restarts within `lease_seconds` (default 30)
without re-init.

## 4. Scaling daemon replicas

```bash
# Scale up / down (the Service's sessionAffinity keeps existing
# consumers stuck to their current backend; new consumer pods get
# the new replica).
kubectl -n <ns> scale deploy/<daemon-deploy> --replicas=<N>
```

**Capacity sizing.** Each replica's
`proxy.max_concurrent_backend_calls` (default 200) bounds peak
concurrency. The thread pool (`proxy.max_blocking_threads`, default
512) sets the hard ceiling. Backend (HSM) hardware concurrency is
the actual bottleneck — if your HSM supports 10 concurrent sessions,
set `max_concurrent_backend_calls` ≈ 20 (some headroom) so the
breaker trips before the HSM rejects.

**HA caveat.** All replicas must read the same `mechanism_params.toml`
(via a single ConfigMap). Drift would cause shim consumers to see
revision-flap warnings.

## 4a. Crash isolation & blast radius — run multiple instances

**The vendor PKCS#11 module is loaded in-process in each daemon.** A SIGSEGV inside
the vendor `.so` therefore takes down **that daemon process** and drops the consumers
pinned to it. (In-process worker isolation — ADR-0007 / the parent-repo design spec
`doc/plans/2026-05-30-backend-process-isolation-design.md` — was evaluated and
**deliberately deferred**: it cannot make a crash transparent, because PKCS#11
session/login/operation state is un-serializable and dies with the backend regardless,
and its remaining wins were not worth the complexity. See the A2 entry in
`doc/follow-up-index.md`.)

**Supported mitigation — "safety" / stable-channel deployment: run multiple daemon
instances and partition consumers across them.** This is the same multi-replica
topology as §4. A backend crash is then contained to the **one** replica's consumers;
the other replicas and their consumers are unaffected, and the orchestrator restarts
the dead replica. No in-process feature is needed.

**Sticky routing is mandatory.** A PKCS#11 session handle is valid **only on the
replica that created it** (sessions live in that replica's backend process). So:

* ✅ Pin each consumer to one replica for its lifetime — the reference manifests do
  this with `sessionAffinity: ClientIP` (§4); a static per-consumer endpoint works too.
* ❌ Never put a round-robin L4 load balancer that spreads a single consumer's calls
  across replicas — you will get `CKR_SESSION_HANDLE_INVALID` storms.

**Consumers must reconnect after a replica restart.** A restart re-initialises the
backend fresh, so the consumer's sessions/login/in-progress operations are gone. The
shim auto-reconnects the gRPC channel with bounded backoff, but the **application** must
re-open its session, re-`C_Login`, and retry — see §6 `CKR_DEVICE_ERROR`. A consumer
that keeps using its pre-crash handles keeps failing.

**For stronger containment,** partition more finely: a dedicated instance per token /
trust-domain, or per high-value consumer, so one consumer's crash-inducing input cannot
affect another's. The cost is N× backend `C_Initialize` and N× resource use.

## 5. Updating mechanism registry (vendor extensions, e.g. CloudHSM)

```bash
# 1) Edit the ConfigMap.
kubectl -n <ns> edit configmap <daemon-config>
# (Or update your Helm values and apply.)

# 2) The daemon reloads the registry on SIGHUP. The simplest way
#    to deliver SIGHUP across all replicas is a rolling restart.
#    Alternatively, exec into each pod and `kill -HUP 1`.
kubectl -n <ns> rollout restart deploy/<daemon-deploy>

# 3) Restart consumer services so their next C_Initialize fetches
#    the new registry. The shim doesn't background-poll the
#    registry — it picks up changes only via reprobe (which runs at
#    every C_Initialize) or full process restart.
kubectl -n <consumer-ns> rollout restart deploy/<consumer-deploy>
```

**Confirm the new revision is live.**

```bash
kubectl -n <ns> logs deploy/<daemon-deploy> | jq -c 'select(.fields.message=="mechanism registry ready") | .fields'
# {"discovery_mode":"transparent","param_shapes":52,"parameterless":162,"revision":"05b1bd2c615bde04"}
```

The `revision` field is a SHA-256-prefix of the loaded TOML. New
contents produce a new revision.

### ConfigMap `subPath` caveat

K8s ConfigMaps mounted with `subPath` **do not auto-update** when the
ConfigMap is edited. Use a regular volume mount so the daemon sees
edits to `mechanism_params.toml` within ~60 s of `kubectl apply`,
then send SIGHUP to reload. The reference manifest at
`pkcs11-proxy-ng/examples/k8s/20-daemon-deployment.yaml` already
uses the directory-mount pattern.

```yaml
# RIGHT: full directory mount, picks up updates.
volumeMounts:
  - name: proxy-config
    mountPath: /etc/pkcs11-proxy-ng
volumes:
  - name: proxy-config
    configMap:
      name: pkcs11-proxy-ng-config

# WRONG: subPath stays frozen at pod-create time. Only fix is
# kubectl rollout restart, defeating the SIGHUP reload flow.
# volumeMounts:
#   - name: proxy-config
#     mountPath: /etc/pkcs11-proxy-ng/proxy.toml
#     subPath: proxy.toml
```

## 6. Troubleshooting common CK_RV codes

### CKR_DEVICE_ERROR (0x30)

**Most likely cause — ambiguous, two sources.** Either (a) a transport-level
failure to the daemon — pod restart, network partition, daemon overload
(circuit-breaker trip); or (b) a **backend-reported error** forwarded unchanged.
Some modules use `CKR_DEVICE_ERROR` as a catch-all: e.g. kryoptic returns it for its
crypto-backend (OpenSSL) path, so a rejected `C_Verify`, an integrity failure, or an
unmapped crypto error surfaces here too. The proxy does not invent a "network error"
code (ADR-0003 §5), so this value alone cannot tell the two apart. **To distinguish:**
a transport failure clears on the shim's automatic reconnect/retry; a backend error
persists on retry. The authoritative "daemon restarted, re-initialize" signal is
`CKR_CRYPTOKI_NOT_INITIALIZED` (below), **not** this code.

**Triage.**

1. Is the consumer pod stable? `kubectl get pods -l app=<consumer>`.
2. Is the daemon Service reachable from the consumer pod?
   `kubectl -n <consumer-ns> exec <consumer-pod> -- sh -c
   "(echo > /dev/tcp/<daemon-svc>/7512) && echo ok"` (bash) — or
   try connecting via the shim's own `pkcs11-proxy-ng-cli list-slots`.
3. Are the daemon's logs showing circuit-breaker trips?
   `kubectl -n <ns> logs deploy/<daemon> | jq -c '. | select(.fields.message | startswith("Backend circuit breaker"))'`.
4. If breakers are tripping, check backend (HSM) capacity vs.
   `proxy.max_concurrent_backend_calls`.

**Recovery.** Usually transient — the shim's bounded-backoff
reconnect path restores the channel without app intervention. If
errors persist, roll back the daemon to a known-good image or scale
it up.

### CKR_CRYPTOKI_NOT_INITIALIZED (0x190)

**Most likely cause.** Daemon restart beyond `lease_seconds`
(default 30) — the previous `client_context_id` is gone, the shim
detected it, and is asking the app to re-init.

**Triage.**

1. Was the daemon restarted? `kubectl -n <ns> get pods -l app=<daemon> -o wide`
   — check pod ages.
2. If yes, the application must call `C_Finalize` + `C_Initialize`
   (ThalesGroup `crypto11` does this automatically; raw `miekg/pkcs11`
   users must handle it themselves).

**Recovery.** Bounce the consumer service so it gets a fresh
`C_Initialize`. If the consumer keeps hitting this repeatedly, the
daemon may be unstable — investigate via daemon logs.

### CKR_TOKEN_NOT_PRESENT (0xE0)

**Most likely cause.** Slot/token-scoped RPC (e.g. `C_GetSlotList`)
hit while the daemon was unreachable.

**Triage / recovery.** Same as `CKR_DEVICE_ERROR`. The CK_RV
difference is which entry point the application hit; the underlying
remedy is the same.

### NOT_SERVING readiness probe

The daemon's `tonic-health` reports `NOT_SERVING` during
graceful-shutdown drain and (when fully wired — see follow-ups) when
the backend exceeds `backend_health_consecutive_failures`. k8s pulls
the pod out of the Service endpoint pool.

**Triage.**

1. Recent restart? Normal during drain. `kubectl logs ... | jq -c 'select(.fields.message | contains("SIGTERM"))'`.
2. Backend hang? `kubectl logs ... | jq -c 'select(.fields.message | contains("Backend call timed out"))'`.
3. Persistent NOT_SERVING + healthy daemon = wedged backend; restart
   the daemon to force `populate_slots` to re-discover.

### "Private/secret key not found" / CKR_OBJECT_HANDLE_INVALID

**Most likely cause.** New daemon replica doesn't have the key in
its backend store. This is the *shared-backend* assumption breaking
down — see the SRE/ops audit's "shared backend storage" finding.

**Triage / recovery.** Verify the `tokens` (or HSM-specific) volume
in the daemon deployment is mounted from a shared backend (PVC,
hostPath that's actually shared, or a network HSM endpoint). NEVER
use `emptyDir` for the backend tokens in a multi-replica setup.

## 7. On-call flowchart

```
  Consumer pod is reporting PKCS#11 errors / pages fired
                            │
                            ▼
        Are daemon pods healthy (kubectl get pods)?
              │                              │
              ▼                              ▼
            Yes                              No
              │                              │
              ▼                              ▼
   Are recent restarts /         Was there a rollout, OOMKill,
   rollouts in progress?         or node eviction?
       │             │              │            │
       ▼             ▼              ▼            ▼
      Yes           No            Yes           No
       │             │              │            │
       ▼             ▼              ▼            ▼
  Wait for         Probably    Investigate:    Investigate
  rollout to       backend     describe pod,   node + HSM
  finish; verify   (HSM) is    check resource  hardware
  consumer        unhappy.     limits, HSM
  recovers.      Check daemon  client logs.
                 logs for
                 "Backend …
                 timed out".
                       │
                       ▼
              Restart the daemon
              (often clears HSM-
              client state).
```

## 8. Useful one-liners

```bash
# Stream all daemon JSON logs across replicas, jq-parsed:
kubectl -n <ns> logs -f -l app=<daemon> | jq -c .

# Just WARN/ERROR levels:
kubectl -n <ns> logs -f -l app=<daemon> | jq -c 'select(.level=="WARN" or .level=="ERROR")'

# Watch backend-call counters via the daemon's own internal eviction-task log:
kubectl -n <ns> logs -f -l app=<daemon> | jq -c 'select(.fields.message | contains("backend call usage"))'

# Check which mechanism registry revision a daemon replica loaded:
kubectl -n <ns> logs deploy/<daemon> | jq -c 'select(.fields.message=="mechanism registry ready") | .fields.revision'

# Force a daemon registry reload without restarting:
kubectl -n <ns> exec deploy/<daemon> -- kill -HUP 1
```

## 8a. Environment variable overrides

The daemon honours a small set of env vars that override TOML fields,
useful in container/k8s deployments where the TOML is supplied via a
ConfigMap and per-pod values need late-binding.

| Variable | TOML field | Notes |
| --- | --- | --- |
| `PKCS11_PROXY_BIND` | `listener.remote.bind` | Creates an insecure-TCP listener if `[listener.remote]` is absent in the TOML; mTLS / auth still come from TOML. |
| `PKCS11_PROXY_BACKEND_MODULE` | `backend.module` | Absolute path to the backend `.so`. |
| `PKCS11_PROXY_BACKEND_ARGS` | `backend.initialize_args` | Backend-specific `C_Initialize` args (e.g. NSS config-dir spec). |
| `PKCS11_PROXY_MECHANISMS_CONFIG` | `mechanisms.config_path` | Path to the mechanism registry served to shims. |

**Precedence (lowest → highest):** TOML defaults < TOML file < environment.

The same table can be printed from the binary itself:

```
pkcs11-proxy-ng --print-env-vars
```

`--print-env-vars` exits 0 without loading the config — safe to call
from a healthcheck or a Dockerfile-style sanity probe.

## 8b. Shim env vars (consumer side)

The shim is a `.so` loaded by the application; it has no CLI, so its
configuration is purely via env vars. The application's environment
controls which proxy the shim connects to and how.

### Connection

| Variable | Purpose | Notes |
| --- | --- | --- |
| `PKCS11_PROXY_ENDPOINT` | gRPC endpoint URL, e.g. `http://daemon:7512` or `https://daemon:7512` | Canonical. Wins over `PKCS11_PROXY_SOCKET` if both are set. |
| `PKCS11_PROXY_SOCKET` | Back-compat with the original C `pkcs11-proxy`. Accepts only `tcp://host:port`; `tls://` is **not** supported (use mTLS via `PKCS11_PROXY_ENDPOINT=https://…` + `PKCS11_PROXY_TLS_*`). | Logged as a translation warning. |
| `PKCS11_PROXY_CONNECT_TIMEOUT` | Connect timeout, seconds. Default `5`. | Plain integer. |

### mTLS (client side)

| Variable | Purpose |
| --- | --- |
| `PKCS11_PROXY_TLS_CA_CERT` | Path to a PEM trust anchor for verifying the daemon's server cert. |
| `PKCS11_PROXY_TLS_CLIENT_CERT` | Path to the shim's client cert PEM. |
| `PKCS11_PROXY_TLS_CLIENT_KEY` | Path to the shim's client private key PEM. |
| `PKCS11_PROXY_TLS_DOMAIN` | SNI / cert-name override; usually unnecessary when the endpoint hostname matches the cert. |

All four are required together for mTLS; setting just one is an
error.

### Mechanism registry

| Variable | Purpose |
| --- | --- |
| `PKCS11_PROXY_MECHANISMS` | Path to a TOML override file the shim layers on top of its embedded default registry at `C_Initialize`. Used only until the server-published registry arrives via `GetBackendInterfaces`. |
| `PKCS11_PROXY_DISABLE_SERVER_REGISTRY` | If set to any value, the shim ignores the server-published registry and uses only the embedded default + `PKCS11_PROXY_MECHANISMS` override. Test/debug use only — production should leave this unset so vendor mechanisms picked up by the daemon's `[mechanisms].config_path` are honoured. |

## 9. Known limitations

These are documented limitations that an on-call engineer may
encounter; they are scope of follow-up rounds:

| Limitation | Workaround | Owner |
| --- | --- | --- |
| FOLLOWUP-fork-safety: forked children of a `C_Initialize`d shim must `C_Finalize`+`C_Initialize` to recover | Use fork-then-exec in consumer apps | Application code (not daemon-side) |
| Backend crash blast radius: a vendor-`.so` SIGSEGV downs the whole daemon process (backend is in-process; A2/in-process-worker deferred) | Run **multiple instances + sticky routing** (§4a); consumers reconnect + re-open (§6) | Deployment + application code |

Earlier follow-ups (DNS re-resolve, slow-backend test, per-RPC
trace ID, gRPC health probe, rate-limiter) are closed.

## 10. Escalation

If the daemon is repeatedly crashing or returning errors and this
runbook does not resolve the issue:

1. Collect daemon + consumer logs:
   `kubectl -n <ns> logs -l app=<daemon> --all-containers --tail=1000 > daemon.log`
2. Capture the rendered configmaps:
   `kubectl -n <ns> get configmap <daemon-config> -o yaml > config.yaml`
3. Open an issue with the above attached, plus a description of the
   change that preceded the symptoms (image bump, config edit, scale
   change, backend HSM rotation, …).

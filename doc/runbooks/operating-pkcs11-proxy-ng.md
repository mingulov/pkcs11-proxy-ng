# Operating pkcs11-proxy-ng — Runbook

| Companion docs | |
| --- | --- |
| CK_RV reference | [`doc/error-reference.md`](../error-reference.md) |
| Reference k8s manifests | [`examples/k8s/`](../../examples/k8s/) |
| Example configs (dev/staging/prod) | [`examples/configs/`](../../examples/configs/) |

## v0.2 single-client testing boundary

Use one logical client in one trusted security domain per daemon and provider
instance. Restart both before handing the instance to an independent client or
domain, even after disconnect or logout. `[proxy] max_contexts = 1` limits
admission but does not clear native login state. Independent clients need
separate daemon/provider instances; shared HSM or token isolation needs its
own validation. See the [v0.3 scope](../release/v0.3.0-scope.md) for
multi-client work.

## v0.2 native-lifetime stop (implemented; candidate qualification separate)

If native shutdown cannot safely finish, the daemon attempts a whole-process
exit with status 70. A completed stop ends other client threads in a direct
embedding. Use one managed provider chain per process. The admitted Linux
paths use raw `exit_group(70)` on GNU/musl x86_64, x86, and aarch64; target
admission is separate from release qualification. See the
[native ownership contract](../release/native-mechanism-ownership.md).

Configure the supervisor to restart on exit status 70. For systemd,
`Restart=on-failure` or `always` can cover it; `on-abnormal` and `on-abort`
do not. Container entrypoints must pass through the daemon's exit status.

Allow `exit_group(70)` under seccomp and other syscall filters. Arbitrary
syscall denial or interception is unsupported, and there is no strict exit
deadline. This stop does not run cleanup, wipe retained secrets, or flush the
audit tail; token effects may be unresolved. Configure core dumps, collectors,
storage, and process inspection accordingly. `RLIMIT_CORE=0` alone does not
disable piped core collectors.

## 0. Prerequisites

* Kubernetes 1.28 or newer and `kubectl`; `jq` helps with log triage.
* A backend PKCS#11 module accessible to each daemon replica. SoftHSM2 is
  suitable for the demo; production deployments need their intended provider.
* For mTLS, a CA and certificates for the daemon and each shim client.

## 1. Install (first deploy)

```bash
# 1) Build and publish a runnable daemon image to your registry.
#    The APK carrier image (packaging/alpine/Dockerfile.alpine) is
#    FROM scratch — it only stages APKs at /apk and cannot run.
#    Likewise tests/r2_resilience/Dockerfile.daemon builds a test-only
#    fixture (weak PINs, auth="none"): use it as the pattern for your
#    runtime Dockerfile, not as a release image.
The commands below use the Kubernetes demo manifests, which contain fixed PINs
and unauthenticated TCP. For a real deployment, use the
[mTLS guide](../release/mtls-setup.md), set per-client authorization, and
provide your own runtime image and manifests.

```bash
# 1) Package the daemon and provider in a runnable image and publish it.
#    Dockerfile.alpine produces APKs only; it is not the runtime image.
docker build --build-arg ALPINE_BUILD_IMAGE=alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0 \
  -f packaging/alpine/Dockerfile.alpine \
  -t pkcs11-proxy-ng:test-alpine3.23 .
docker build -f <your-runtime-Dockerfile> \
  -t <registry>/pkcs11-proxy-ng:<version>-alpine3.23 .
docker push <registry>/pkcs11-proxy-ng:<version>-alpine3.23

# 2) Apply the reference manifests (or your Helm overlay), pointed at
#    the image you just published.
kubectl apply -f pkcs11-proxy-ng/examples/k8s/
kubectl apply -f examples/k8s/
kubectl -n pkcs11-proxy-demo set image deploy/daemon \
  daemon=<registry>/pkcs11-proxy-ng:<version>-alpine3.23

# 3) Edit the ConfigMap to point at your backend module.
kubectl -n pkcs11-proxy-demo edit configmap daemon-config
# Replace [backend].module with the path inside the daemon container.

# 4) Trigger a rollout to pick up the edited config.
kubectl -n pkcs11-proxy-demo rollout restart deploy/daemon
kubectl -n pkcs11-proxy-demo rollout status deploy/daemon
```

**Smoke test.** List slots and sign once through the shim. The
`examples/k8s/` consumer also runs a repeated signing check; its manifests
use demo credentials and unauthenticated TCP.

## 2. Rolling upgrade

```bash
# 1) Bump the image tag in the daemon Deployment.
kubectl -n <ns> set image deploy/<daemon-deploy> daemon=<registry>/pkcs11-proxy-ng:<new-version>-alpine3.23

# 2) Watch the rolling update.
kubectl -n <ns> rollout status deploy/<daemon-deploy>

# 3) Verify consumer traffic stayed clean. If you have the
#    reference consumer StatefulSet, its log shows
#    `success`/`recoverable`/`unrecoverable` counts every 20 ops.
```

The demo manifests use `sessionAffinity: ClientIP`, `maxSurge: 1`, and
`maxUnavailable: 0`. Check consumer results during and after the rollout;
the observed demo result is not a guarantee for a different provider.

**Upgrade shim and daemon together.** Mixed versions are unsupported. Older
peers can lose the distinction between a NULL parameter pointer and a present
empty buffer for GCM, OAEP, and CCM; providers may return different results.
Validate the parameter shapes your deployment uses before the rollout.

**If consumer reports unrecoverable errors during the rollout:**

1. Check pod readiness: `kubectl -n <ns> get pods -l app=<daemon-deploy>`.
2. If a new replica fails readiness, the rollout pauses. Investigate with
   `kubectl describe pod` and `kubectl logs`.
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

After rollback, verify that consumers reconnect, reopen sessions if needed,
and can sign or perform their normal operation.

## 4. Scaling daemon replicas

```bash
# Scale up / down (the Service's sessionAffinity keeps existing
# consumers stuck to their current backend; new consumer pods get
# the new replica).
kubectl -n <ns> scale deploy/<daemon-deploy> --replicas=<N>
```

**Capacity sizing.** Each replica's `proxy.max_concurrent_backend_calls`
(default 200) limits simultaneous backend calls; `proxy.max_blocking_threads`
(default 512) is the thread ceiling. Size these for the provider's measured
capacity and watch for circuit-breaker trips.

Keep the mechanism registry consistent across replicas so clients see the
same mechanism list after reconnecting.

## 4a. Crash isolation & blast radius — run multiple instances

**The vendor PKCS#11 module is loaded in-process in each daemon.** A SIGSEGV inside
the vendor `.so` therefore takes down **that daemon process** and drops the consumers
pinned to it. (In-process worker isolation was evaluated and
**deliberately deferred**: it cannot make a crash transparent, because PKCS#11
session/login/operation state is un-serializable and dies with the backend regardless,
and its remaining wins were not worth the complexity.)

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
The vendor PKCS#11 module runs inside the daemon. A crash in that module ends
the daemon process and drops its clients' sessions and in-progress operations.

Run separate daemon instances for separate trusted clients or domains. A
provider crash then affects clients assigned to that instance; the supervisor
can restart it.

**Keep each consumer on one replica.** A session handle is valid only on the
replica that created it.

* Use `sessionAffinity: ClientIP` as in the demo, or a fixed endpoint per client.
* Do not spread one client's calls across replicas; its handles will fail with
  `CKR_SESSION_HANDLE_INVALID`.

After a replica restart, the shim reconnects, but the application must reopen
sessions, log in again, and reestablish operations. Old handles are invalid.

Dedicated instances cost more provider connections and memory. Size the
deployment for those costs.

## 4b. Windows daemon operations (x64/MSVC)

The Windows daemon runs Windows provider DLLs over mTLS/TCP. The release ZIP
is produced by `scripts/release-windows.sh`.

- Configure `[listener.remote]` with `auth = "mtls"`. Windows rejects
  `[listener.local]` because Unix peer credentials are unavailable.
- Restart the daemon to apply mechanism-registry or config changes. Run it
  under a service or scheduled-task supervisor.
- Install the MSVC C runtime (`vcruntime140.dll`); otherwise the executable
  fails before it can log.
- For SoftHSM2 testing, initialize the token with `softhsm2-util.exe` on the
  Windows host. Set `SOFTHSM2_CONF`, put SoftHSM2's `lib/` directory on
  `Path`, and confirm initialization with a slot listing.
- An unsafe native shutdown attempts to end the whole process with status 70.
  Configure the supervisor to restart when it observes that status; see the
  [native ownership contract](../release/native-mechanism-ownership.md).

## 5. Updating mechanism registry (vendor extensions, e.g. CloudHSM)

```bash
# 1) Edit the ConfigMap.
kubectl -n <ns> edit configmap <daemon-config>
# (Or update your Helm values and apply.)

# 2) The daemon reloads the registry on SIGHUP. The simplest way
#    to get the new registry live across all replicas is a rolling restart.
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

### Shipped vendor overlays

`examples/vendors/` retains example registry entries for provider integration.
The following standard mechanisms are already in the embedded default registry:

- `bouncyhsm-blake2b.toml` — `BLAKE2B_*_HMAC_GENERAL`
  (OASIS v3.2 standard `0x400E/0x4013/0x4018/0x401D`, single-`CK_ULONG`
  `mac_general` shape).
- `opencryptoki-ecdh-x-cof.toml` — `CKM_ECDH_X_AES_KEY_WRAP` /
  `CKM_ECDH_COF_AES_KEY_WRAP` (`0x4038/0x4039`, `ecdh_aes_key_wrap`
  shape).

No overlay is needed to enable those standard entries. For a customized registry,
set `[mechanisms].config_path` (or `PKCS11_PROXY_MECHANISMS` for a local shim),
then reload per §5. Mechanism discovery still reflects the selected provider.

### ConfigMap `subPath` caveat

K8s ConfigMaps mounted with `subPath` **do not auto-update** when the
ConfigMap is edited. Use a regular volume mount so the daemon sees
edits to `mechanism_params.toml` within ~60 s of `kubectl apply`,
then send SIGHUP to reload. The reference manifest at
`examples/k8s/20-daemon-deployment.yaml` already
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

### Authorization policy edits require a restart

Unlike the mechanism registry above, the `[auth.policy]` token policy is
loaded once at startup and is NOT reloaded on SIGHUP. Editing the policy
therefore requires a daemon restart (`kubectl rollout restart`), and
contexts already open keep the grants captured at their `C_Initialize`.

## 6. Troubleshooting common CK_RV codes

### CKR_DEVICE_ERROR (0x30)

**Most likely cause — ambiguous, two sources.** Either (a) a transport-level
failure to the daemon — pod restart, network partition; or (b) a
**backend-reported error** forwarded unchanged. (Daemon overload /
circuit-breaker trips surface as `CKR_HOST_MEMORY`, and backend-call
timeouts as `CKR_FUNCTION_FAILED` — see `doc/error-reference.md`
for the full proxy-originated mapping.)
Some modules use `CKR_DEVICE_ERROR` as a catch-all: e.g. kryoptic returns it for its
crypto-backend (OpenSSL) path, so a rejected `C_Verify`, an integrity failure, or an
unmapped crypto error surfaces here too. The proxy does not invent a "network error"
code (ADR-0003 §5), so this value alone cannot tell the two apart. **To distinguish:**
a transport failure clears on the shim's automatic reconnect/retry; a backend error
persists on retry. The authoritative "daemon restarted, re-initialize" signal is
`CKR_CRYPTOKI_NOT_INITIALIZED` (below), **not** this code.
Providers can also return `CKR_DEVICE_ERROR` for their own failures. Match
the request ID in daemon logs to determine whether the provider returned it.
Do not infer the cause from this code alone. A lost context after restart
surfaces as `CKR_CRYPTOKI_NOT_INITIALIZED`.

**Triage.**

1. Is the consumer pod stable? `kubectl get pods -l app=<consumer>`.
2. Can the consumer reach the daemon? Run the CLI's `list-slots` command
   from the consumer environment using the configured endpoint and mTLS files.
3. Are the daemon's logs showing circuit-breaker trips?
   `kubectl -n <ns> logs deploy/<daemon> | jq -c '. | select(.fields.message | startswith("Backend circuit breaker"))'`.
4. If breakers are tripping, check backend (HSM) capacity vs.
   `proxy.max_concurrent_backend_calls`.

**Recovery.** The shim reconnects after a transient transport failure. For
persistent errors, inspect the provider and recent changes before deciding
whether to roll back or add capacity. Reconcile state before retrying a
non-idempotent call.

### CKR_CRYPTOKI_NOT_INITIALIZED (0x190)

**Most likely cause.** Daemon restart beyond `lease_seconds`
(default 30) — the previous `client_context_id` is gone, the shim
detected it, and is asking the app to re-init.

**Triage.**

1. Was the daemon restarted? `kubectl -n <ns> get pods -l app=<daemon> -o wide`
   — check pod ages.
2. If yes, the application must call `C_Finalize` and `C_Initialize`, then
   reopen its sessions.

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

The daemon's health endpoint reports `NOT_SERVING` during
graceful-shutdown drain and after repeated unhealthy backend outcomes exceed
`backend_health_consecutive_failures`. Kubernetes pulls
the pod out of the Service endpoint pool.

**Triage.**

1. Recent restart? Normal during drain. `kubectl logs ... | jq -c 'select(.fields.message | contains("SIGTERM"))'`.
2. Backend hang? `kubectl logs ... | jq -c 'select(.fields.message | contains("Backend call timed out"))'`.
3. Persistent NOT_SERVING + healthy daemon = wedged backend; restart
   the daemon to force `populate_slots` to re-discover.

### "Private/secret key not found" / CKR_OBJECT_HANDLE_INVALID

**Likely cause.** A new daemon replica cannot see the key in its provider's
store. The demo uses shared SoftHSM2 storage on one node; other deployments
need provider-appropriate shared access.

**Triage / recovery.** Verify the `tokens` (or provider-specific) volume
is shared by the intended replicas, or confirm each replica reaches the same
network HSM. A per-pod `emptyDir` creates separate token stores.

### CKR_USER_ALREADY_LOGGED_IN on a consumer that never logged in (0x100)

A previous context may still hold the slot login. The provider can return
`CKR_USER_ALREADY_LOGGED_IN` without checking the new PIN, so this result
cannot establish that the new client authenticated. Do not retry with a
different PIN.

Check daemon logs for the login holder and wait for it to log out, close its
last session, finalize, or expire. If the holder has stopped but the warning
`Login reconciling holderless-but-logged-in backend` repeats, inspect the
matching `last-holder backend logout` warning and provider behavior. Use a
fresh daemon/provider instance for a new independent client or a test that
requires pristine state.

## 7. On-call checklist

1. Check daemon pod health and recent restarts with `kubectl -n <ns> get pods`.
2. If a rollout is running, check its status and the consumer's operation
   results. If a pod is failing, use `kubectl describe pod` and daemon logs to
   identify startup, resource, or provider errors.
3. If pods are healthy but calls fail, match the request ID in daemon logs.
   Check the provider and the [error reference](../error-reference.md) before
   retrying a call whose outcome may be unknown.
4. After a daemon restart, have the application reopen sessions and log in
   again. Confirm its normal operation succeeds.

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
| `PKCS11_PROXY_BIND` | `listener.remote.bind` | TCP listen address; with no `[listener.remote]` block it creates an unauthenticated listener only if `PKCS11_PROXY_ALLOW_INSECURE=1`. |
| `PKCS11_PROXY_BACKEND_MODULE` | `backend.module` | Absolute path to the backend PKCS#11 `.so` the daemon dlopens. |
| `PKCS11_PROXY_BACKEND_ARGS` | `backend.initialize_args` | Backend-specific `C_Initialize` args string (e.g. NSS config dir spec). |
| `PKCS11_PROXY_MECHANISMS_CONFIG` | `mechanisms.config_path` | Path to the mechanism_params.toml registry served to shims. |
| `PKCS11_PROXY_ALLOW_INSECURE` | `listener.remote.allow_insecure_tcp` | Set to 1 to let `PKCS11_PROXY_BIND` create an unauthenticated TCP listener. |
| `PKCS11_PROXY_RESILIENCE_METRICS_SOCKET` | `resilience.metrics_socket` | Unix-domain metrics endpoint path; serves Prometheus text on GET /metrics (mode 0600). |
| `PKCS11_PROXY_RESILIENCE_FIND_THRESHOLD` | `resilience.find_result_warn_threshold` | `C_FindObjects` result size above which a pathological-population event is counted and logged. |
| `PKCS11_PROXY_TEST_HOOKS_CONTROL_SOCKET` | `test_hooks.control_socket` | Hook-gated control endpoint path (mode 0600); requires a native-owner-test-hooks build, default builds fail closed. |

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
| `PKCS11_PROXY_ENDPOINT` | gRPC endpoint URL, e.g. `http://daemon:7512`, `https://daemon:7512`, or `unix:/run/proxy.sock` | Canonical. Wins over `PKCS11_PROXY_SOCKET` if both are set. |
| `PKCS11_PROXY_SOCKET` | Back-compat with the original C `pkcs11-proxy`. Accepts only `tcp://host:port`; `tls://` is **not** supported (use mTLS via `PKCS11_PROXY_ENDPOINT=https://…` + `PKCS11_PROXY_TLS_*`). | `tls://` is a loud error that fails the connection (never falls back to the default endpoint); other non-`tcp://` values log a warning and use the default. |
| `PKCS11_PROXY_CONNECT_TIMEOUT` | Connect timeout, seconds. Default `5`. | Plain integer. |
| `PKCS11_PROXY_CONNECT_ATTEMPTS` | Max gRPC connect attempts per `C_Initialize` (bounded backoff + jitter). Default `10`. | Lower it to fail fast on an unreachable daemon; clamped to `1..=10` — it cannot raise the cap. |

### mTLS (client side)

| Variable | Purpose |
| --- | --- |
| `PKCS11_PROXY_TLS_CA_CERT` | Path to a PEM trust anchor for verifying the daemon's server cert. |
| `PKCS11_PROXY_TLS_CLIENT_CERT` | Path to the shim's client cert PEM. |
| `PKCS11_PROXY_TLS_CLIENT_KEY` | Path to the shim's client private key PEM. |
| `PKCS11_PROXY_TLS_DOMAIN` | SNI / cert-name override; usually unnecessary when the endpoint hostname matches the cert. |

The first three are required together — setting only one or two is
an error that fails the connection. `PKCS11_PROXY_TLS_DOMAIN` is
optional: an SNI / server-cert-name override for when the endpoint
hostname does not match the certificate.

### Mechanism registry

| Variable | Purpose |
| --- | --- |
| `PKCS11_PROXY_MECHANISMS` | Path to a TOML override file the shim layers on top of its embedded default registry at `C_Initialize`. Used only until the server-published registry arrives via `GetBackendInterfaces`. |
| `PKCS11_PROXY_DISABLE_SERVER_REGISTRY` | If set (except an explicit falsy `0`/`false`/`no`/`off`, which re-enables), the shim ignores the server-published registry and uses only the embedded default + `PKCS11_PROXY_MECHANISMS` override. Test/debug use only — production should leave this unset so vendor mechanisms picked up by the daemon's `[mechanisms].config_path` are honoured. Value parsing is defined by `server_registry_disabled` in `crates/shim/src/interface_probe.rs`: empty, unrecognized, and non-UTF8 values keep the legacy disable (deliberate fail-legacy). |

## 8c. Private diagnostic bundles

Run `scripts/collect-debug-bundle.sh` to create an archive under
`target/debug-bundles/`, or use `--output-dir` for an owned directory. The
collector requires a private output directory and creates the archive with
mode `0600`. It fails if the output path changes during collection.

The archive includes an allowlist of system and tool versions, Git state,
provider/build artifact presence, and whether selected environment variables
are set. It excludes environment values, raw logs, config files, command
errors, and workspace contents. `--include-logs` is rejected because arbitrary
logs cannot be sanitized automatically.

Extract and inspect every file before sharing the archive. If logs or config
fragments are needed, review and redact them separately; share only the
relevant excerpt.

## 9. Known limitations

These limits may affect a deployment:

| Limitation | Workaround | Owner |
| --- | --- | --- |
| FOLLOWUP-fork-safety: forked children of a `C_Initialize`d shim must `C_Finalize`+`C_Initialize` to recover | Use fork-then-exec in consumer apps | Application code (not daemon-side) |
| Backend crash blast radius: a vendor-`.so` SIGSEGV downs the whole daemon process (backend is in-process; A2/in-process-worker deferred) | Run **multiple instances + sticky routing** (§4a); consumers reconnect + re-open (§6) | Deployment + application code |
| Multiplexed daemon vs pristine token: N logical clients share one backend instance per slot — no per-context pristine state (see below) | Rotate/restart the daemon for pristine-state cases; partition daemons per tenant (§4a) | Test harness / deployment |
| Message-Init struct strictness: classic param structs on message Init fail closed (`CKR_MECHANISM_PARAM_INVALID`); lenient backends accept them direct (see below) | Pack the `CK_*_MESSAGE_PARAMS` struct for the mechanism on message Init | Application code |
| Login-timing observer: an authorized session owner can tell proxy-cooldown `CKR_PIN_LOCKED` (fast, no backend contact) from a forwarded attempt, and observes its own login state (see below) | Accepted residual — no constant-latency guarantee by design | — |
| Suspended session handles count toward the per-principal session quota; unset quotas bound nothing (see below) | Set `per_principal_max_sessions` where tenants are untrusted | Deployment |
| Daemon memory lock is best-effort (`mlockall`, loud on denial); shim has no process-wide lock; swap residual stands (see below) | Grant `CAP_IPC_LOCK` / `LimitMEMLOCK`, confirm the startup log line | Deployment |
| Git-sourced dependencies need network unless the cargo cache is pre-populated; no vendored sources ship (see below) | Pre-populate the cargo cache for air-gapped builds | Build |
| `tests/consumers/Dockerfile.daemon.kryoptic` is unpinned/unhashed fixture-only (see below) | Never use fixture images outside provider-matrix testing | Test harness |

### Multiplexed daemon vs pristine token (in-memory backends)

One daemon = one loaded backend module = **one token state per slot shared
by every logical client** (ADR-0002 §6, ADR-0007). The proxy multiplexes
handles, sessions, and login scoping, but it does **not** give each context a
pristine token. In-memory backends (kryoptic, jcardsim, non-persistent
SoftHSM) make this visible: token objects, backend login state, and
find-enumeration all accumulate across tenants sharing the daemon.

What the daemon does and does not reset between tenants:

* **Per-context cleanup (always):** a departing context's backend sessions
  are closed (only when unreferenced by live contexts), its virtual handles
  invalidated, its session objects destroyed with their sessions.
* **Shared state (by design, persists):** the backend login while any live
  context holds it (released on last-context-out, D6(2)/D9); token objects
  any tenant created; anything the backend itself remembers (jcardsim
  key files, kryoptic in-memory tables).
* **Consequences for assertions:** a case that logs in while a prior case's
  context still lives gets `CKR_USER_ALREADY_LOGGED_IN` (§6) — correct
  multiplexed behavior, not a bug. A case asserting an empty token, a
  logged-out token, or a private-object population it did not create is
  asserting **pristine** state and is invalid against a shared daemon.
* **Find-enumeration login filtering (F-04, fixed):**
  `C_FindObjects` results are filtered by the querying context's login
  state: a logged-out context observes only known-public objects' bare
  (virtual) handles/counts, even while another tenant holds the backend
  logged in (unknown privacy hides fail-closed). Attribute reads, every
  use path, and private-object create/copy/generate still refuse with
  `CKR_USER_NOT_LOGGED_IN` as before.

**Rule for harnesses:** cases needing pristine state must rotate to a fresh
daemon (restart, or a per-case backend namespace/volume) — the D9-harness
rotation option. Cases tolerant of multiplexing may share, but must treat
`ALREADY` as "slot held" and must scope their assertions to objects they
created. For strict tenant isolation in production, partition daemons per
tenant exactly as for crash containment (§4a).
| forked children of a `C_Initialize`d shim must `C_Finalize`+`C_Initialize` to recover | Use fork-then-exec in consumer apps | Application code (not daemon-side) |
| A vendor module crash ends the daemon process | Use separate instances and keep each client on one replica (§4a); reopen sessions after restart (§6) | Deployment + application code |
| Message-Init struct strictness: classic param structs on message Init fail closed (`CKR_MECHANISM_PARAM_INVALID`); lenient backends accept them direct | Pack the `CK_*_MESSAGE_PARAMS` struct for the mechanism on message Init | Application code |
| Login attempts in proxy cooldown return `CKR_PIN_LOCKED` sooner than forwarded attempts | No constant-latency guarantee | Application |
| Suspended session handles count toward the per-principal session quota; unset quotas bound nothing | Configure the quota for the trusted testing client; quotas do not qualify untrusted multi-tenancy | Deployment |
| Daemon memory lock is best-effort (`mlockall`, loud on denial); shim has no process-wide lock; swap residual stands | Grant `CAP_IPC_LOCK` / `LimitMEMLOCK`, confirm the startup log line | Deployment |

### Single-client lifetime and backend-authoritative login

Restart the daemon/provider before handing it to an independent client.
Persistent token objects may remain after a restart; tests needing an empty
token must provision one separately.

An admitted `C_Login` reaches the provider, which decides whether to check
the PIN and which return value to send. `CKR_USER_ALREADY_LOGGED_IN` does
not establish a new logical login. Object filtering and context cleanup do
not qualify this daemon for mutually untrusted clients; see the
[privacy contract](../release/privacy.md).

### Message-Init struct strictness (classic structs fail closed)

`C_MessageEncryptInit` and `C_MessageDecryptInit` require the message
parameter struct for the mechanism (`CK_GCM_MESSAGE_PARAMS`,
`CK_CCM_MESSAGE_PARAMS`, or `CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS`).
Classic structs such as `CK_GCM_PARAMS` and `CK_CCM_PARAMS` return
`CKR_MECHANISM_PARAM_INVALID` before reaching the provider. Some providers
accept those classic structs directly, so check the caller's packed struct
when this error appears only through the proxy.

### Login-timing observer

After session checks pass, a login attempt in the shared per-slot cooldown
returns `CKR_PIN_LOCKED` without contacting the provider. An authorized
session owner can distinguish that quick refusal from a forwarded attempt.
There is no constant-latency guarantee.

### Suspended handles and session quotas

A session close in progress suspends its handle until the provider reports
completion. Suspended handles count toward an enabled per-principal session
quota. Quotas are unset by default; set `per_principal_max_sessions` to
bound session use for the trusted client. Quotas do not add support for
mutually untrusted clients.

### Memory lock and swap

At startup the daemon attempts `mlockall(MCL_CURRENT | MCL_FUTURE)` so
PIN/key pages cannot swap; denial (typically missing `CAP_IPC_LOCK`
or a restrictive `RLIMIT_MEMLOCK`) and non-Unix platforms log a loud
warning with remediation and the daemon still starts. The shim has no
process-wide lock. Without the lock, daemon pages can reach swap
under memory pressure and outlive the process — wiping clears live
copies on drop but cannot reach already-swapped pages (see
[privacy](../release/privacy.md)). Operators who need the guarantee
grant the capability (systemd `LimitMEMLOCK=infinity` +
`CapabilityBoundingSet=CAP_IPC_LOCK`, or `setcap cap_ipc_lock+ep`)
and confirm the startup log shows the pages-locked line.

### Login-timing observer (accepted residual)

After context/session checks pass, a login attempt that hits the
shared per-slot failed-login budget answers `CKR_PIN_LOCKED` fast,
without contacting the backend — measurably faster than a forwarded
attempt. An authorized session owner can therefore observe (a) whether
the slot is in proxy cooldown (shared budget state) and (b) its own
resulting login state. There is deliberately no constant-latency
guarantee: no jitter, no generic return code, no extra HSM calls to
mask the difference. The observer must already hold an authorized
session, which bounds the exposure; accept it as designed.

### Suspended handles and session quotas (accepted residual)

A session close in flight parks its handle "suspended" (safety
quarantine): stale completions are no-ops, and the handle either
reactivates on transient failure or is removed on terminal
completion. Suspended handles keep their slot registration, so the
opt-in per-principal session quota counts them — fail-closed against
quota evasion via rapid open/close churn. With quotas unset (the
default), in-flight closes are unbounded in principle: completions
always resolve them, but no bound was proven under adversarial
scheduling. A new cap needs resource-policy design and is deferred;
set `per_principal_max_sessions` where tenants are untrusted.

### Memory lock and swap residual (accepted residual)

At startup the daemon attempts `mlockall(MCL_CURRENT | MCL_FUTURE)` so
PIN/key pages cannot swap; denial (typically missing `CAP_IPC_LOCK`
or a restrictive `RLIMIT_MEMLOCK`) and non-Unix platforms log a loud
warning with remediation and the daemon still starts. The shim has no
process-wide lock. Without the lock, daemon pages can reach swap
under memory pressure and outlive the process — wiping clears live
copies on drop but cannot reach already-swapped pages (see
[privacy](../release/privacy.md)). Operators who need the guarantee
grant the capability (systemd `LimitMEMLOCK=infinity` +
`CapabilityBoundingSet=CAP_IPC_LOCK`, or `setcap cap_ipc_lock+ep`)
and confirm the startup log shows the pages-locked line.

### Git-sourced dependencies (accepted residual)

`pkcs11-module` (backend, shim) is consumed from a rev-pinned git URL
(`pkcs11-components`), not from crates.io, and no vendored sources
ship with the release. Builds fetch it over the network unless the
cargo cache is already populated. For air-gapped builds, pre-populate
the cache (a normal online build once) — offline distribution beyond
that is deferred, not part of v0.2.

### Unpinned provider-matrix fixtures (accepted residual)

`tests/consumers/Dockerfile.daemon.kryoptic` builds from unpinned
`alpine:3.23` bases, an unhashed kryoptic checkout, an unhashed
OpenSSL source pull, and an unlocked rustup stable toolchain: the
image is not reproducible and makes no release claim. It is a
provider-matrix test fixture only. Fixture pinning is separate,
optional work — it is not part of the release dependency closure,
which stays fully locked (`Cargo.lock`, digest-pinned release
images).

## 10. Escalation

If the daemon is repeatedly crashing or returning errors and this
runbook does not resolve the issue:

1. Run `scripts/collect-debug-bundle.sh`, extract the resulting archive, and
   review every file before attaching it.
2. If the allowlisted bundle is insufficient, collect only the relevant daemon
   or consumer log interval. Review it for PINs, key material, credentials,
   object values, and identifying metadata before sharing it. The bundle
   collector does not sanitize or include logs.
3. Describe the non-secret configuration fields and the change that preceded
   the symptoms (image bump, config edit, scale change, backend HSM rotation,
   and so on). Do not attach a rendered ConfigMap or full environment dump by
   default; these commonly contain credentials.

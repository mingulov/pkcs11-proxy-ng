# Operating pkcs11-proxy-ng — Runbook

> **Reading bar.** The engineer who gets paged at 3 am should be
> able to resolve the incident using this document alone, without
> opening source code.

| Companion docs | |
| --- | --- |
| CK_RV reference | [`doc/error-reference.md`](../error-reference.md) |
| Reference k8s manifests | [`examples/k8s/`](../../examples/k8s/) |
| Example configs (dev/staging/prod) | [`examples/configs/`](../../examples/configs/) |

## v0.2 native-lifetime stop (pending implementation and qualification)

The selected [native ownership contract](../release/native-mechanism-ownership.md)
uses qualified Linux GNU/musl x86_64/64-bit and x86/32-bit raw `exit_group(70)`
for unresolved native shutdown or unsafe final-owner Drop. It ends the whole
daemon thread group, affecting every co-located client. Direct embedders also
accept termination of unrelated application threads. One managed provider chain
per process is required; partition independent chains into separate daemons.

The supervisor must observe the actual daemon's ordinary nonzero status:
systemd on-failure/always can cover 70, on-abnormal/on-abort alone cannot.
Success/restart-prevention settings, rate limits and manual stops still apply;
container entrypoints must propagate status and Docker needs an appropriate
restart policy. Namespace PID 1 termination affects other container processes;
global host init is excluded. No strict disappearance deadline is promised.

All potential invoking threads and later filters must allow exit_group(70).
Arbitrary seccomp denial, tracing or syscall interception is unsupported; the
return-aware loop prevents fallthrough but cannot force a denied group exit.
The stop runs no cleanup, wiping or audit flush, so the audit tail and token
effects may remain unresolved. It does not intentionally trigger a core or
enforce global dump suppression: operators own dump/collector/storage policy,
including piped collectors not disabled by RLIMIT_CORE=0 alone. Read the linked
contract before enabling native embeddings; these are future enforcement gates,
not capabilities supplied by this documentation change.

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

**Shim/daemon lockstep.** The shim and daemon must be upgraded together
(same release) — mixed-version peers are not supported. An old shim
sends no `iv_null`/`aad_null`/`source_null` bits, so a new daemon
materializes empty GCM/OAEP fields as non-NULL where the old daemon
forced NULL (templates are unaffected — the default matches old
behavior). Lockstep peers are exact; on backends that distinguish the
shapes the skew only flips between two reject codes, never
accept↔reject. (Wave 3.5 D2/F3 review Finding 2.)

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

## 4b. Windows daemon operations (x64/MSVC)

The Windows daemon (`pkcs11-proxy-ng.exe` from the deterministic ZIP bundle,
`scripts/release-windows.sh`) runs Windows provider DLLs behind mTLS-over-TCP
only. Evidenced on real Windows Server 2022; receipts at workspace-root
`artifacts/v020-tail-windows-2026-09-16/leg-A-daemon-win/` unless noted.

- **Listener: `[listener.remote]` with mTLS, no `[listener.local]`.** Unix
  sockets + peer-cred auth do not exist on Windows; the leg-A daemon config
  (`proxy-config-legA.toml`) carries only `[listener.remote]`. A config that
  includes `[listener.local]` fails fast at startup, exit 1:
  `"[listener.local] (unix socket + peer-cred) is not supported on this OS;
  configure [listener.remote] with auth = 'mtls' instead"` (exact stderr in
  `leg-B-shim-win/listener-local-negative.utf8.log`).
- **No SIGHUP reload — restart to apply.** Mechanism-registry or config changes
  require a daemon restart; there is no signal reload on Windows. The leg-A
  run used a scheduled-task launcher (`run-daemon-legA.ps1`) because
  session-owned processes die with the SSH session — prefer a
  service/scheduled-task supervisor over ad-hoc shells.
- **MSVC CRT prerequisite.** The guest needs the MSVC C runtime
  (`vcruntime140.dll` present in System32 on the Server 2022 receipt host);
  a missing CRT fails the binary before any proxy log line.
- **Token provisioning via the guest `softhsm2-util.exe`.** Initialize the
  token on the guest with the provider's own tool, with `SOFTHSM2_CONF`
  pointed at the guest config and the SoftHSM2 `lib/` dir prepended to
  `Path` (the leg-A run hit the PATH gotcha: without it the util cannot find
  its DLLs). `--version` output is not proof — re-run a slot/token listing
  and keep it (`token-show-slots.utf8.log` shows slot 1513421618, label
  `png-t6-legA`, `Initialized: yes`).
- **Abnormal stop is whole-process, status 70.** Same contract as Linux, via
  `TerminateProcess(GetCurrentProcess(), 70)`; supervise with
  `Restart=on-failure` semantics (see the stop section at the top of this
  runbook and the
  [native ownership contract](../release/native-mechanism-ownership.md)).

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

`examples/vendors/` carries ready-to-layer overlays for mechanisms the
proxy understands structurally but keeps operator opt-in rather than
enabling by default:

- `bouncyhsm-blake2b.toml` — `BLAKE2B_*_HMAC_GENERAL`
  (OASIS v3.2 standard `0x400E/0x4013/0x4018/0x401D`, single-`CK_ULONG`
  `mac_general` shape; kept opt-in per the Wave 3 F2 sketch, promotion
  to defaults is defensible follow-up).
- `opencryptoki-ecdh-x-cof.toml` — `CKM_ECDH_X_AES_KEY_WRAP` /
  `CKM_ECDH_COF_AES_KEY_WRAP` (`0x4038/0x4039`, `ecdh_aes_key_wrap`
  shape; kept opt-in pending dedicated X/COF shapes).

Point `[mechanisms].config_path` (or `PKCS11_PROXY_MECHANISMS` for a
local shim) at the overlay, or `include` it from the daemon's registry
file, then reload per §5.

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

### CKR_USER_ALREADY_LOGGED_IN on a consumer that never logged in (0x100)

**Expected behavior — one logical login holder per slot.** All logical
clients of a daemon share one backend token per slot (ADR-0002 §6). While
**any** live context holds the slot login, the backend token is logged in
and would answer a second `C_Login` with `CKR_USER_ALREADY_LOGGED_IN`
*without checking the PIN* — so the daemon cannot PIN-verify the new login
and returns that answer faithfully instead of minting a login on an
unverified PIN (Wave 3.5 D6(3); a different user type gets
`CKR_USER_ANOTHER_ALREADY_LOGGED_IN`). The presented PIN is not evaluated
at all on this path.

**Triage.**

1. This is contention, not corruption: another live consumer (or a previous
   test case whose context lease has not expired yet) holds the slot login.
   Find it via daemon logs (`Login succeeded` with a different context id).
2. The window is bounded: `C_Logout`, last-session close, `C_Finalize`, and
   lease expiry each release the backend login as soon as no live context
   holds it (D6(2)/D9). Retry the login after the holder releases.
3. If logins starve, the holder is leaking its login (never logs out and
   holds sessions open past its useful life). Fix the holder; do not share
   one daemon across tenants that need concurrent independent logins on the
   same token — partition daemons per tenant (§4a).
4. A `Login reconciling holderless-but-logged-in backend` warning means an
   earlier best-effort last-holder logout was skipped or failed (find the
   cause in the matching `last-holder backend logout` warning); the login
   self-heals with one backend logout plus a single retry. Occasional
   reconciles after teardown races are benign; repeated ones point at a
   token that never auto-logs-out or a wedged logout path — investigate.

**Test-harness note.** Back-to-back cases sharing one daemon (e.g. the ncli
suites) routinely hit this when a prior case's context is still within its
lease: treat `ALREADY` after a prior login as "slot still held", rotate to a
fresh daemon for pristine-state cases (see §9), and never work around it by
retrying with a different PIN — the PIN is not the problem.

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
| `PKCS11_PROXY_DISABLE_SERVER_REGISTRY` | If set to any value, the shim ignores the server-published registry and uses only the embedded default + `PKCS11_PROXY_MECHANISMS` override. Test/debug use only — production should leave this unset so vendor mechanisms picked up by the daemon's `[mechanisms].config_path` are honoured. |

## 8c. Private diagnostic bundles

Run `scripts/collect-debug-bundle.sh` to create a small diagnostic archive under
`target/debug-bundles/`, or select an owned output directory with
`--output-dir`. The final output directory must be owned by the invoking user
and must not be group- or world-writable; missing components are created with
mode `0700`. The collector retains a no-follow descriptor for that directory,
uses a unique create-only archive name for concurrent runs, and creates the
archive with mode `0600`. Directories and regular files represented inside the
archive have modes `0700` and `0600` respectively. If the validated path is
replaced while collection is running, collection fails and removes only the
partial archive inode it created.

The archive contains only explicitly allowlisted metadata: normalized system
and tool versions, the Git commit and dirty-state boolean, presence of known
provider/build artifacts, and whether selected environment variables are set.
It does not contain environment values, raw logs, configuration files, command
errors, arbitrary paths, or workspace file contents. `--include-logs` is
intentionally rejected because arbitrary logs cannot be generically sanitized.
Archive construction uses Python's standard-library `tarfile` and `gzip`
implementations with fixed member names, types, modes, timestamps, numeric
owners, and no gzip filename. It does not invoke `tar`, `gzip`, or `mktemp`, and
does not consume `TAR_OPTIONS` or `GZIP`. The shell entrypoint therefore needs
only Bash and Python 3.9 or newer; the collector is intended for the project's
supported Linux environment.

The private mode protects the archive on the machine where it is created; it
does not make the contents anonymous or suitable for automatic publication.
Always extract and review every file before sharing. If logs or configuration
details are essential, review and redact them separately and attach only the
minimum necessary excerpt.

## 9. Known limitations

These are documented limitations that an on-call engineer may
encounter; they are scope of follow-up rounds:

| Limitation | Workaround | Owner |
| --- | --- | --- |
| FOLLOWUP-fork-safety: forked children of a `C_Initialize`d shim must `C_Finalize`+`C_Initialize` to recover | Use fork-then-exec in consumer apps | Application code (not daemon-side) |
| Backend crash blast radius: a vendor-`.so` SIGSEGV downs the whole daemon process (backend is in-process; A2/in-process-worker deferred) | Run **multiple instances + sticky routing** (§4a); consumers reconnect + re-open (§6) | Deployment + application code |
| Multiplexed daemon vs pristine token: N logical clients share one backend instance per slot — no per-context pristine state (see below) | Rotate/restart the daemon for pristine-state cases; partition daemons per tenant (§4a) | Test harness / deployment |
| Message-Init struct strictness: classic param structs on message Init fail closed (`CKR_MECHANISM_PARAM_INVALID`); lenient backends accept them direct (see below) | Pack the `CK_*_MESSAGE_PARAMS` struct for the mechanism on message Init | Application code |

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

### Message-Init struct strictness (classic structs fail closed)

`C_MessageEncryptInit` / `C_MessageDecryptInit` must carry the message
parameter struct for the mechanism (`CK_GCM_MESSAGE_PARAMS`,
`CK_CCM_MESSAGE_PARAMS`, `CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS`).
Passing the classic struct (`CK_GCM_PARAMS`, `CK_CCM_PARAMS`) fails
closed with `CKR_MECHANISM_PARAM_INVALID` by design (ADR-0010
Limits-(c)) — the call never reaches the backend. kryoptic and NSS
leniently accept classic structs on message Init, so such calls pass
direct and fail proxied; that is a documented strictness divergence, not
a proxy bug (Wave 3 §7.3, Ruling 3 — see the report erratum). If a
consumer hits `CKR_MECHANISM_PARAM_INVALID` on message Init only through
the proxy, check the packed struct first.

Earlier follow-ups (DNS re-resolve, slow-backend test, per-RPC
trace ID, gRPC health probe, rate-limiter) are closed.

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

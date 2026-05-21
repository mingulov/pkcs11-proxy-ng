# Example daemon configs (R9)

Three environment-tier reference configs that drop straight into a
k8s `ConfigMap` or a bare-metal `/etc/pkcs11-proxy-ng/proxy.toml`.

| Tier | File | Transport | Backend | Log level |
| --- | --- | --- | --- | --- |
| dev | `dev/proxy.toml` | insecure TCP on loopback | SoftHSM2 | debug |
| staging | `staging/proxy.toml` | mTLS | NSS softokn | info |
| prod | `prod/proxy.toml` | mTLS | HSM placeholder (must edit) | warn |

## Dry-run any of them

```bash
# Builds the daemon, parses the config, exits before binding.
# Useful for catching schema drift before deploy.
cargo run -p pkcs11-proxy-ng -- --help

# Or, for the actual TOML parse + validation:
target/debug/pkcs11-proxy-ng examples/configs/dev/proxy.toml
# (will block on listener bind — Ctrl+C is fine for the dry-run.)
```

## File permission requirements

The daemon refuses to start (R9 verification 2) if any mTLS private
key file is group/world-readable. Recommended modes:

```bash
chmod 0600 /etc/pkcs11-proxy-ng/tls/server.key
chmod 0644 /etc/pkcs11-proxy-ng/tls/server.crt
chmod 0644 /etc/pkcs11-proxy-ng/tls/ca.crt
chmod 0644 /etc/pkcs11-proxy-ng/proxy.toml
chmod 0644 /etc/pkcs11-proxy-ng/mechanism_params.toml
```

## ConfigMap subPath caveat (R9 verification 4)

K8s ConfigMaps mounted via `subPath` **do not auto-update** when the
ConfigMap is edited. Use a regular volume mount (no `subPath`) so the
daemon sees `kubectl edit configmap` updates within ~60 s, then send
`SIGHUP` to reload the mechanism registry.

```yaml
volumes:
  - name: proxy-config
    configMap:
      name: pkcs11-proxy-ng-config

containers:
  - name: daemon
    volumeMounts:
      # Right: full directory mount, picks up updates.
      - name: proxy-config
        mountPath: /etc/pkcs11-proxy-ng
      # WRONG: subPath stays frozen at pod-create time.
      # - name: proxy-config
      #   mountPath: /etc/pkcs11-proxy-ng/proxy.toml
      #   subPath: proxy.toml
```

## Forward compatibility (R9 verification 5)

New `[proxy]` fields ship with `#[serde(default)]` so older configs
parse cleanly against newer daemons. Validate before deploy:

```bash
target/debug/pkcs11-proxy-ng examples/configs/<tier>/proxy.toml
```

A parse error indicates either a typo or a missing required field
(e.g. `backend.module`), not forward-compat breakage.

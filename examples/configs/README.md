# Example daemon configs

These examples show daemon settings for development, staging, and production.
Edit paths, certificates, and authorization policy for your deployment before
using one.

| Tier | File | Transport | Backend | Log level |
| --- | --- | --- | --- | --- |
| dev | `dev/proxy.toml` | insecure TCP on loopback | SoftHSM2 | debug |
| staging | `staging/proxy.toml` | mTLS | NSS softokn | info |
| prod | `prod/proxy.toml` | mTLS | HSM placeholder (must edit) | warn |

## Check a config

```bash
cargo build -p pkcs11-proxy-ng
# Parse the TOML and start the daemon. Stop it with Ctrl+C after checking logs.
target/debug/pkcs11-proxy-ng examples/configs/dev/proxy.toml
```

## File permission requirements

The daemon refuses a group- or world-readable mTLS private key. Suggested
file modes:

```bash
chmod 0600 /etc/pkcs11-proxy-ng/tls/server.key
chmod 0644 /etc/pkcs11-proxy-ng/tls/server.crt
chmod 0644 /etc/pkcs11-proxy-ng/tls/ca.crt
chmod 0644 /etc/pkcs11-proxy-ng/proxy.toml
chmod 0644 /etc/pkcs11-proxy-ng/mechanism_params.toml
```

## ConfigMap subPath caveat

Kubernetes ConfigMaps mounted through `subPath` do not update in a running
pod. Mount the full directory to receive updates, then send `SIGHUP` to
reload the mechanism registry. Authorization policy changes require a daemon
restart.

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

## Forward compatibility

Run the config check above with the daemon version you plan to deploy. A
startup error may indicate a typo or missing required field such as
`backend.module`.

# mTLS Setup

For TCP connections, configure mutual TLS on the daemon and shim. This guide
creates a CA, a server certificate, and one client certificate.

> For same-host deployments, use a Unix socket with peer-credential auth; see
> [Unix-domain socket](#unix-domain-socket-alternative).

## 1. Generate certificates

This `openssl` example is for evaluation. Use your organization's CA and key
management for a real deployment.

```bash
# Certificate authority
openssl req -x509 -newkey ed25519 -nodes -days 825 \
  -keyout ca.key -out ca.crt -subj "/CN=pkcs11-proxy-ng CA"

# Server cert (CN/SAN must match what the client expects, see PKCS11_PROXY_TLS_DOMAIN)
openssl req -newkey ed25519 -nodes -keyout server.key -out server.csr \
  -subj "/CN=proxy.example.internal" \
  -addext "subjectAltName=DNS:proxy.example.internal"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -copy_extensions copy -out server.crt

# Client cert (its issuer/subject is the client identity for authorization)
openssl req -newkey ed25519 -nodes -keyout client.key -out client.csr \
  -subj "/CN=app-1"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -out client.crt
```

## 2. Lock down private-key permissions

The daemon **rejects** an mTLS private key that is group- or world-accessible; a
server key must be mode `0600` (or stricter). This is enforced at startup.

```bash
chmod 0600 server.key client.key
```

## 3. Daemon configuration

In the daemon's TOML (`[listener.remote]`):

```toml
[listener.remote]
bind        = "0.0.0.0:7512"
auth        = "mtls"
ca_cert     = "/etc/pkcs11-proxy-ng/tls/ca.crt"
server_cert = "/etc/pkcs11-proxy-ng/tls/server.crt"
server_key  = "/etc/pkcs11-proxy-ng/tls/server.key"

[auth]
# Evaluation only: accept any client with a CA-signed cert.
allow_all_authenticated = true
# For production, remove this setting and restrict each certificate identity
# to specific tokens; see the operator runbook for policy syntax.
```

See the [staging](../../examples/configs/staging/proxy.toml) and
[production](../../examples/configs/prod/proxy.toml) examples for complete
configurations.

## 4. Client configuration

The shim is configured by environment variables:

```bash
export PKCS11_PROXY_ENDPOINT=https://proxy.example.internal:7512
export PKCS11_PROXY_TLS_CA_CERT=/path/to/ca.crt
export PKCS11_PROXY_TLS_CLIENT_CERT=/path/to/client.crt
export PKCS11_PROXY_TLS_CLIENT_KEY=/path/to/client.key
# Only if the cert SAN differs from the endpoint host:
export PKCS11_PROXY_TLS_DOMAIN=proxy.example.internal

# then point the application at the shim:
#   --module /usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so
```

## Unix-domain socket alternative

For same-host deployments, run the daemon on a Unix socket with
peer-credential authentication (no certificates), and point the client at it:

```bash
export PKCS11_PROXY_ENDPOINT=unix:/run/pkcs11-proxy-ng/proxy.sock
```

The daemon authenticates the connecting process by its OS credentials
(`SO_PEERCRED`). Use `PKCS11_PROXY_ENDPOINT` for Unix sockets;
`PKCS11_PROXY_SOCKET` accepts only legacy `tcp://` addresses. See the
[operator runbook](../runbooks/operating-pkcs11-proxy-ng.md) for the local
listener configuration.

## Verify

```bash
pkcs11-tool --module /usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so --list-slots
```

A successful slot listing over the configured transport confirms the handshake
and authorization path.

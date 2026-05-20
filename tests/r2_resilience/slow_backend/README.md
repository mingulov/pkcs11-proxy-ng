# slow-backend — stub PKCS#11 `.so` with configurable delays

Closes `R2-FOLLOWUP-slow-backend` (cross-references
`R4-FOLLOWUP-mock-backend`).

The R2 resilience round can simulate network slowness via toxiproxy
but cannot simulate slow backends. This stub `.so` exposes a minimal
PKCS#11 v2.40 surface and reads three env vars on each call:

| Env var | Effect |
| --- | --- |
| `SLOW_BACKEND_SIGN_DELAY_MS` | Sleep this long in `C_Sign` / `C_SignFinal` before returning OK |
| `SLOW_BACKEND_INIT_DELAY_MS` | Sleep this long in `C_Initialize` |
| `SLOW_BACKEND_INIT_HANG=1` | Block forever in `C_Initialize` (kill-only recovery) |

Everything cryptographic returns
`CKR_FUNCTION_NOT_SUPPORTED` — the backend is for lifecycle / timeout
testing only.

## Build

```bash
cd tests/r2_resilience/slow_backend
cargo build --release
# → target/release/libslow_backend.so
```

The crate is intentionally NOT a workspace member (`[workspace]`
sentinel in its Cargo.toml) so `cargo build --workspace` at the
submodule root doesn't pay its build cost.

## Use with the daemon

```toml
# proxy.toml
[backend]
module = "/path/to/libslow_backend.so"

[proxy]
request_timeout_secs = 2   # short so the backend timeout fires fast
```

```bash
SLOW_BACKEND_SIGN_DELAY_MS=5000 pkcs11-proxy-ng /etc/proxy.toml
```

Then drive any shim consumer that calls `C_Sign`. Each call sleeps 5
seconds in the backend; the daemon's `spawn_backend()` timeout (2 s
above) trips and the consumer sees `CKR_DEVICE_ERROR`, the daemon's
circuit-breaker counter advances, and after
`backend_health_consecutive_failures` consecutive failures
`tonic-health` flips to `NOT_SERVING`.

## Smoke test

A minimal C program that confirms the `.so` dlopens and
`C_GetFunctionList` returns OK:

```c
#include <dlfcn.h>
typedef unsigned long CK_RV;
typedef CK_RV (*GFL)(void**);

int main() {
    void *h = dlopen("./target/release/libslow_backend.so", 2);
    GFL g = (GFL)dlsym(h, "C_GetFunctionList");
    void *fl = 0;
    return g(&fl);  // 0 on success
}
```

## Scope

Sufficient for: lifecycle timeout testing, circuit-breaker testing,
SIGTERM-during-slow-call testing.

NOT sufficient for: any consumer test that actually needs valid
signature output, mechanism advertising, or working session state.
For that, use SoftHSM2 / NSS softokn / Kryoptic from
`tests/consumers/`.

# Slow backend test module

This PKCS#11 2.40 test module injects delays and errors inside the daemon's
backend calls. The network resilience fixture uses toxiproxy for faults between
the shim and daemon.

| Env var | Effect |
| --- | --- |
| `SLOW_BACKEND_SIGN_DELAY_MS` | Delay `C_Sign` and `C_SignFinal` by this many milliseconds |
| `SLOW_BACKEND_INIT_DELAY_MS` | Sleep this long in `C_Initialize` |
| `SLOW_BACKEND_INIT_HANG=1` | Block forever in `C_Initialize` (kill-only recovery) |
| `SLOW_BACKEND_SIGN_RV_HEX` | Return this hex `CK_RV` from `C_Sign` after any delay |
| `SLOW_BACKEND_BREAK_AFTER_CALLS` | After this many calls, make subsequent backend calls fail |
| `SLOW_BACKEND_BREAK_RV_HEX` | Hex `CK_RV` after the break; defaults to `0x2` (`CKR_HOST_MEMORY`) |
| `SLOW_BACKEND_VERBOSE=1` | Print per-call diagnostic output |

The module returns a fixed, noncryptographic signature for `C_Sign`. Other
operations provide only enough behavior for lifecycle and timeout tests. Do
not use its output as a real signature.

## Build

```bash
cd tests/r2_resilience/slow_backend
cargo build --release
# → target/release/libslow_backend.so (glibc, for host use)

# For Alpine / musl daemon containers, build via rust:alpine:
docker run --rm -v "$PWD:/src" -w /src --entrypoint sh \
    rust:1.94-alpine -c \
    "apk add --no-cache build-base >/dev/null && \
     RUSTFLAGS='-C target-feature=-crt-static' cargo build --release"
# → target/release/libslow_backend.so (musl, for Alpine daemon)
```

The crate has its own `[workspace]` in `Cargo.toml`, so build it separately
from the main workspace.

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

Then use a shim consumer to call `C_Sign`. With this configuration, the backend
waits five seconds while the daemon's two-second request timeout expires. The
consumer receives `CKR_FUNCTION_FAILED`; the native call may still complete.
The daemon counts consecutive backend failures and reports `NOT_SERVING` once
`backend_health_consecutive_failures` is reached.

## Load check

This minimal C program checks that the library loads and
`C_GetFunctionList` returns success:

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

Use this module for lifecycle timeouts, circuit-breaker behavior, and shutdown
during a slow call. Use SoftHSM2, NSS softokn, or Kryoptic from
`tests/consumers/` for tests that require real cryptographic output, advertised
mechanisms, or working session state.

# musl proven tier (x86_64 static + Alpine execution, T4)

v0.2.0 proves musl at the **static-build + Alpine-execution + live-smoke
tier** for `x86_64-unknown-linux-musl`: the release bundle builds
reproducibly for the musl target, every artifact executes natively on
Alpine (no glibc anywhere), and the serving shapes complete a live
SoftHSM2-backed smoke. Re-run any time with
`scripts/run-musl-test.sh` (local docker route; the per-PR Tier 0g
`musl-x86_64` CI job runs the same build commands).

## Linkage split (read this first)

musl law shapes the tier — a static binary cannot `dlopen` (musl
answers `Dynamic loading not supported`), and a cdylib cannot link
statically. So the route builds four artifacts in two linkages:

| Artifact | Linkage | Proven |
| --- | --- | --- |
| `pkcs11-proxy-ng` (static) | static-pie, no interpreter | Builds; executes `--version` on Alpine. Cannot load backends (negative receipt below, asserted in the script). |
| `pkcs11-proxy-ng-cli` | static-pie, no interpreter | Builds; executes; drives the whole live smoke (the CLI never dlopens). |
| `pkcs11-proxy-ng` (dynamic) | musl-dynamic, `/lib/ld-musl-x86_64.so.1` | Builds; boots on Alpine against SoftHSM2; serves the full smoke. This is the serving shape — the same shape `packaging/alpine/APKBUILD` ships. |
| `libpkcs11_proxy_ng_shim.so` | musl-dynamic cdylib | Loads on Alpine; full pkcs11-tool smoke through it (slots, RSA-2048 keygen, SHA256-RSA-PKCS sign). Runtime deps: musl libc + platform `libgcc_s` (`apk add libgcc`). |

The static daemon is a build-and-execute receipt only; the DO-NOT-USE
stale reading is "static daemon serves backends" — it cannot, on any
musl system, by musl design (the proxy code already documents this in
`crates/backend/src/ffi/loading.rs`, and the Alpine stage re-proves
it live on every run).

## Proven (2026-09-18)

Build toolchain: `Dockerfile.musl` (Debian 13) with rustc 1.98.1
(`RUST_TOOLCHAIN` pin, override with `--build-arg`), musl-tools
1.2.5 (`musl-gcc` driver; there is no triplet-prefixed
`x86_64-linux-musl-gcc` on Debian/Ubuntu — that wrong name was the
freeze-gate failure), Debian gcc 14.2.0 (static libgcc.a +
`libgcc_s.so.1` `@@GCC_3.0` unwind symbols only — its `libc.so.6`
edge is transitive and never transfers), `protoc` 3.21.12.
Proof image: `alpine:3.23`
(`sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0`,
3.23.6) with softhsm-2.6.1-r6, opensc-0.26.1-r0, musl-1.2.5-r23,
libgcc-15.2.0-r2, file-5.46-r2 — all x86_64, all from Alpine repos.

- **Static build:** `cargo build --release --target
  x86_64-unknown-linux-musl -p pkcs11-proxy-ng -p pkcs11-proxy-ng-cli`
  clean (ring compiles against musl via `CC_x86_64_unknown_linux_musl=musl-gcc`).
- **Dynamic build:** shim + daemon with
  `scripts/musl-dynamic-link-flags.sh`
  (`-C target-feature=-crt-static` plus a `-L` redirect resolving
  rustc's explicit `-lgcc_s` at `GROUP(libgcc.a, libgcc_s.so.1)` —
  the cross musl-gcc wrapper cannot resolve `-lgcc_s` on its own).
  Same script feeds the CI leg, so both stay in sync.
- **`file` receipts:** static daemon + CLI report `static-pie linked`
  with no `interpreter` line; dynamic daemon reports `interpreter
  /lib/ld-musl-x86_64.so.1`; shim reports `shared object,
  dynamically linked`.
- **`--version` receipts on Alpine:** `pkcs11-proxy-ng 0.2.0`
  (both daemons), `pkcs11-proxy-ng-cli 0.2.0`.
- **Negative receipt:** the static daemon exits 1 against a real
  backend config with `native module load failed: Dynamic loading
  not supported` — the musl limit, asserted load-bearingly (if musl
  ever allows static dlopen, the script fails and this doc must be
  revised).
- **Daemon boot:** the dynamic daemon loads SoftHSM2
  (`Backend module loaded and initialized`, `Slot map populated`),
  publishes the mechanism registry, and serves (`Health status:
  SERVING`), including the documented insecure-TCP startup WARN.
- **CLI live ops (static CLI):** `list-slots` → `Slot 1`, `Slot 2`;
  `token-info 1` → the `musl-smoke` SoftHSM2 token.
- **Shim smoke:** pkcs11-tool through the musl shim lists the token,
  generates an RSA-2048 keypair, and produces a 256-byte
  SHA256-RSA-PKCS signature.
- **Linkage hygiene:** `ldd` on Alpine resolves the shim and the
  dynamic daemon to the musl loader + musl `libc.so` +
  `/usr/lib/libgcc_s.so.1` only — no `libc.so.6`, nothing unresolved;
  the proof box has no glibc loader installed at all.

## Still excluded

- **Serving from a static daemon is NOT claimed** (impossible — see
  above). No mock-backend exception was added: the production musl
  daemon is musl-dynamic, and a mock-serving static binary would prove
  nothing about proxy work.
- **i686-musl stays intentionally absent.** The musl claim is x86_64
  Alpine packaging only (same exclusion the Tier 0f comment states).
- **No musl provider-parity claim.** The direct-vs-proxied matrix
  stays glibc-x86_64; musl coverage is one SoftHSM2-backed smoke.
- **No static-daemon FFI qualification change.** `NATIVE_FFI_QUALIFIED`
  already includes musl/Linux x86_64; the static limit is enforced by
  musl itself at `dlopen`, before any proxy code runs.

## How to re-run

```bash
scripts/run-musl-test.sh            # full route: build + Alpine proof
scripts/run-musl-test.sh --quick    # skip the RSA keygen + sign steps
scripts/run-musl-test.sh --build-only  # build + file receipts, no Alpine stage
```

`MUSL_MODE=host` uses a host musl toolchain (rustup target +
musl-tools + protoc) instead of docker for the build steps; the
Alpine stage always uses docker. `MUSL_KEEP_STAGE=1` keeps the
staged artifacts; `MUSL_ALPINE_VER` overrides the proof image
(default `3.23`). CI equivalence: the Tier 0g `musl-x86_64` job runs
the same three `cargo build` invocations (static pair, dynamic pair
via the same flags script) plus the same `file` assertions — the
Alpine execution half lives only in this script.

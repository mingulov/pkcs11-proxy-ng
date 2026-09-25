# x86_64 musl and Alpine Coverage

A recorded `v0.2.0` test built the `x86_64-unknown-linux-musl` artifacts
and ran them on Alpine with SoftHSM2. Run `scripts/run-musl-test.sh` to
repeat the full build and Alpine check. The CI `musl-x86_64` job repeats the
build and file-type checks; the live Alpine stage runs in this script.

## Which artifacts can serve a provider?

A fully static musl binary cannot load a PKCS#11 module with `dlopen`.
The daemon that serves a provider therefore uses dynamic musl linkage.

| Artifact | Recorded result on Alpine |
| --- | --- |
| Static daemon | Builds and runs `--version`; fails to load a real provider, as the script asserts. |
| Static CLI | Builds and runs; performs the live CLI checks against the dynamic daemon. |
| Dynamic daemon | Loads SoftHSM2 and serves requests. This is the form shipped by `packaging/alpine/APKBUILD`. |
| Dynamic shim library | Loads in `pkcs11-tool`; lists slots, generates an RSA-2048 keypair, and signs with SHA256-RSA-PKCS. |

The dynamic daemon and shim need musl and Alpine's `libgcc` package.
The recorded linkage checks found no glibc dependency or unresolved library.
The script also confirmed that the static daemon fails provider loading with
`Dynamic loading not supported`.

## Scope of the result (2026-09-18)

The build used `Dockerfile.musl`, the musl target, and
`scripts/musl-dynamic-link-flags.sh` for the dynamic pair. The Alpine stage
confirmed daemon startup, SoftHSM2 token discovery, CLI slot and token
commands, and the shim key-generation/signing smoke.

This is one live provider smoke, not a full direct/proxy parity comparison.
It does not cover i686 musl or provider serving by the static daemon.
The dynamic daemon is the provider-serving form; static build success alone
does not establish backend runtime support. See the
[support matrix](beta-support-matrix.md) for public and candidate claims.

## Run options

```bash
scripts/run-musl-test.sh            # build and Alpine checks
scripts/run-musl-test.sh --quick    # skip RSA key generation and signing
scripts/run-musl-test.sh --build-only  # build and file checks only
```

`MUSL_MODE=host` uses a host musl toolchain for the build; the Alpine stage
still uses Docker. `MUSL_KEEP_STAGE=1` retains staged artifacts, and
`MUSL_ALPINE_VER` selects the Alpine image (default `3.23`).

# s390x Build and QEMU Coverage

A recorded `v0.2.0` test built for `s390x-unknown-linux-gnu` and ran the
portable suites under QEMU user-mode emulation. This establishes build and
emulated test coverage for that source, not live big-endian provider support
or qualification of later changes. Run `scripts/run-be-qemu-test.sh` to
repeat the check. There is no big-endian CI leg.

## Recorded result (2026-09-23)

The script used `Dockerfile.be-qemu` with a cross compiler and
`qemu-s390x-static`; no s390x hardware was involved. It checked the
workspace and built the shim library. The types, protobuf, client, audit,
CLI, backend, shim, and server suites passed under QEMU, including byte-order
and cross-width tests. The C ABI suite passed for eight of nine cases; its
remaining case was skipped because it also failed on the little-endian
baseline. Native lifetime and provider-gated tests were excluded from this
tier.

## Limits

- The backend refuses native FFI construction on s390x:
  `NATIVE_FFI_QUALIFIED=false`. The required abnormal-stop implementation
  and live provider validation are absent.
- Mixed-endian client/daemon pairs are refused; the supported bridge is
  between peers of the same byte order.
- These tests use mock backends. There is no big-endian direct/proxy provider
  comparison.

The [support matrix](beta-support-matrix.md) separates this historical test
record from public support and current-candidate qualification.

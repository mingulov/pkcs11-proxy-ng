# Development environment

Use the pinned Rust toolchain through rustup (`rust-toolchain.toml`
selects it automatically), with `rustfmt` and `clippy`. The minimum
supported Rust version is **1.88.0**, including when updating dependencies.
The repository builds independently of the umbrella workspace and OASIS
specification checkout.
Use rustup with the toolchain in `rust-toolchain.toml`. The minimum supported
Rust version is **1.88.0**. This repository builds on its own; no planning
workspace or OASIS checkout is needed.

## Ubuntu 24.04 / 26.04

Install the compiler and the tools used by local provider and consumer tests:

```bash
sudo apt update
sudo apt install build-essential pkg-config protobuf-compiler \
    softhsm2 opensc gnutls-bin libnss3-tools
rustup toolchain install 1.98.1 --component rustfmt --component clippy
rustup toolchain install 1.88.0 --profile minimal
cargo install cargo-audit cargo-deny --locked
```

You can also install `protoc` and ShellCheck with
[mise](https://mise.jdx.dev/dev-tools/). Install the provider packages above
separately.

```bash
mise trust
mise install
mise exec -- protoc --version
mise exec -- cargo check --workspace --all-targets --locked
```

Use `mise exec --` when mise is not activated in your shell.

## Core checks

Run from this repository:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo audit
cargo deny check
cargo +1.88.0 build --workspace --locked --all-targets
cargo +1.88.0 test --workspace --locked
scripts/release-dry-run.sh
```

Set `CARGO_BUILD_JOBS=2` if memory is limited. After updating dependencies,
repeat these checks, including the Rust 1.88 build and tests.

## Provider tests

These scripts create temporary development tokens and configurations:

```bash
scripts/test-consumers.sh
scripts/test-shim-parameterized.sh
scripts/test-provider-backends.sh
```

The first two accept `PKCS11_PROXY_BACKEND_MODULE=/absolute/path/to/libsofthsm2.so`.
Keep consumer executables on `PATH`. Other tests search system library paths,
so install your distribution's SoftHSM2 package. NSS tests need `certutil`;
Kryoptic tests use `PKCS11_PROXY_KRYOPTIC_MODULE`.

See the [test guide](../crates/server/tests/README.md) for individual suites
and prerequisites. For broader provider testing, see
[pkcs11-check](https://github.com/mingulov/pkcs11-check).

For manual SoftHSM2 tests, set `SOFTHSM2_CONF` to a configuration with a
user-owned token directory. The scripts above create temporary configurations
and do not need access to the system token store.

## Additional CI lanes

For Linux i686 ABI checks:

```bash
sudo apt install gcc-multilib libc6-dev-i386
rustup target add i686-unknown-linux-gnu
```

For Windows cross-compilation:

```bash
sudo apt install clang lld nasm
rustup target add x86_64-pc-windows-msvc
cargo install cargo-xwin --locked
```

For coverage and Miri:

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
rustup toolchain install nightly --component miri --component rust-src
```

For fuzzing (nightly only; `fuzz/` is excluded from the stable workspace):

```bash
cargo install cargo-fuzz --locked
```

## Fuzzing, Miri, and coverage

The nightly pipeline runs three complementary dynamic gates; all reproduce
locally with the tooling above.

**Fuzz smoke** (`fuzz/`): five libFuzzer harnesses over untrusted-input
edges — `fuzz_width` (cross-ABI `CK_ULONG` translation),
`fuzz_registry` (registry TOML load + queries),
`fuzz_attribute` (attribute proto edge incl. the D8 nesting refusal),
`fuzz_mechanism` (hostile-wire `Mechanism` decode + `CkMechanism`
round-trip over all 79 param shapes), and `fuzz_protected_decode`
(pre-decode wire scanner). Each asserts totality (typed errors, never a
panic) plus edge-specific round-trip invariants. Every target ships
checked-in seeds (`fuzz/seeds/<target>/`); the parser-shaped targets
add libFuzzer dictionaries (`fuzz/dict/*.dict`).

```bash
cargo +nightly fuzz build
for t in fuzz_width fuzz_registry fuzz_attribute fuzz_protected_decode fuzz_mechanism; do
  mkdir -p fuzz/corpus/$t
  cp fuzz/seeds/$t/* fuzz/corpus/$t/
done
cargo +nightly fuzz run fuzz_width -- -max_total_time=90
cargo +nightly fuzz run fuzz_registry -- -max_total_time=90 -dict=fuzz/dict/registry.dict
```

Crashes land in `fuzz/artifacts/<target>/` (git-ignored); reproduce one
with `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>`.
Corpus coverage: `cargo +nightly fuzz coverage <target>` (needs the
`llvm-tools` nightly component), then `llvm-cov report` against the binary
under `target/<triple>/coverage/<triple>/release/<target>`.

**Miri**: the pure width/attribute/mechanism logic, the shim's
raw-pointer parse paths, the shim's pure `tests::` suites (ABI audit,
null-pointer handling, classifier, dispatch shape, endpoint parsing,
regressions, resource limits), and the backend lifecycle/registry
state-machine suites run under the UB interpreter. Daemon/socket/fs
dependent tests self-gate (`#[cfg(not(miri))]` modules,
`cfg_attr(miri, ignore)`, or `cfg!(miri)` skips); the daemon probe is a
no-op under Miri (daemon-down fallback, same as unreachable-daemon).
The exact filter lists live in `nightly.yml` (keep them in sync when
adding UB-relevant pure logic).

**Kani**: `crates/types/src/kani_proofs.rs` proves the width-translation
"never silently truncate" laws plus the attribute-classifier laws
(scalar-shape disjointness, template⇒array-flag,
allocation-size⇒ulong, secret-classification totality) over the whole
input space. Run `cargo kani -p pkcs11-proxy-ng-types`
(pinned verifier; see `nightly.yml`).

**Coverage ratchet**: `cargo llvm-cov --workspace` must stay at or above
84% lines (`--fail-under-lines 84` in `nightly.yml`; baseline 85.20% on
2026-09-28). Bump the floor up as coverage sustainably improves; never
lower it to fit a change — add tests instead.

Target-specific commands are in [ci.yml](../.github/workflows/ci.yml) and
[nightly.yml](../.github/workflows/nightly.yml). Live tests may also need
provider images, 32-bit libraries, or Wine; see the [test guide](../crates/server/tests/README.md).

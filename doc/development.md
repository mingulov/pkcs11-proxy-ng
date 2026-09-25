# Development environment

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

Target-specific commands are in [ci.yml](../.github/workflows/ci.yml) and
[nightly.yml](../.github/workflows/nightly.yml). Live tests may also need
provider images, 32-bit libraries, or Wine; see the [test guide](../crates/server/tests/README.md).

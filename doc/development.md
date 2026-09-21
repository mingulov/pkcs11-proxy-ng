# Development environment

Use the pinned Rust toolchain through rustup (`rust-toolchain.toml`
selects it automatically), with `rustfmt` and `clippy`. The minimum
supported Rust version is **1.88.0**, including when updating dependencies.
The repository builds independently of the umbrella workspace and OASIS
specification checkout.

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

Alternatively, [mise](https://mise.jdx.dev/dev-tools/) can supply `protoc` and
ShellCheck using the versions in `mise.toml`. The native provider packages
above are still needed for tests that discover libraries in system paths.
Rust remains managed by rustup:

```bash
mise trust
mise install
mise exec -- protoc --version
mise exec -- cargo check --workspace --all-targets --locked
```

Use `mise exec --` in CI, editors, or noninteractive shells without mise shell
activation. With mise activated, ordinary `cargo` commands also find `protoc`.

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
cargo +1.88.0 build --workspace --locked
scripts/release-dry-run.sh
```

On a memory-constrained machine, set `CARGO_BUILD_JOBS=2`. Dependencies are
locked deliberately. Before refreshing the lockfile, preview the change with
`cargo update --dry-run --config 'resolver.incompatible-rust-versions="fallback"'`.
Prefer a targeted `cargo update -p <crate>` for an advisory or compatibility
fix, and repeat the advisory, policy, test, and MSRV checks afterward.
Cargo's [Rust-version resolver](https://doc.rust-lang.org/cargo/reference/resolver.html#rust-version)
helps choose compatible versions; the actual Rust 1.88 build remains the gate.

## Provider tests

These scripts create temporary development tokens and configurations:

```bash
scripts/test-consumers.sh
scripts/test-shim-parameterized.sh
scripts/test-provider-backends.sh
```

The first two accept `PKCS11_PROXY_BACKEND_MODULE=/absolute/path/to/libsofthsm2.so`
for a user-local provider installation. Their consumer executables must be
on `PATH`. The Rust SoftHSM2 fixtures and the release smoke script search
system library locations, so install the system SoftHSM2 package to run those
lanes. NSS tests additionally need `certutil` from `libnss3-tools`. Kryoptic
uses `PKCS11_PROXY_KRYOPTIC_MODULE`; see
[`crates/server/tests/README.md`](../crates/server/tests/README.md).

Keep Python packages in uv-managed environments, separate from apt's native
libraries and executables. The `pkcs11-check` framework manages its own
dependencies and does not require PyKCS11. Only the optional
`scripts/test-python-consumer.py` needs PyKCS11; provide it through a separate
[uv script environment](https://docs.astral.sh/uv/guides/scripts/#running-a-script-with-dependencies)
when using that consumer. Do not expose distro Python packages through a
user-site `.pth` file or add them to an unrelated project environment.

The system SoftHSM token store may be restricted to the `softhsm` group.
The scripts above use temporary user-owned configurations and need no access
to that shared store. For manual token work, explicitly set `SOFTHSM2_CONF`
to a user-owned configuration rather than changing shared-store permissions.

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

The exact target-specific commands are in `.github/workflows/ci.yml` and
`.github/workflows/nightly.yml`. Some live tests need additional provider
images, 32-bit provider libraries, or Wine; their prerequisites are separate
from the native Linux development environment.

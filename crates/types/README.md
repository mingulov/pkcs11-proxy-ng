# pkcs11-proxy-ng-types

PKCS#11 value types and the embedded mechanism registry shared across the proxy. This is an implementation crate; Rust applications normally use the client, which re-exports these types.

The four user entry points are the daemon, Rust client, CLI, and C ABI shim. The audit, types, proto, and backend packages support those entry points.

For a full source build, install Rust 1.88 or newer, a native C compiler and linker, `pkg-config`, and `protoc` (often supplied by `protobuf-compiler`). Leaf crates may need fewer tools. The Linux-first testing scope is one logical client in one trusted security domain per daemon/provider instance; a configured provider and daemon are needed for live operations. Crate archives contain source and build inputs, not prebuilt binaries, a provider module, or tokens. See the [project repository](https://github.com/mingulov/pkcs11-proxy-ng) for setup and release guidance.

The published archives support `cargo build`; after the synchronized release is available, the daemon and CLI binaries can be installed with `cargo install pkcs11-proxy-ng` and `cargo install pkcs11-proxy-ng-cli`. The client and shim archives include examples that can be compiled with `cargo check --example remote_client` and `cargo check --example cross_width_smoke` respectively; running them may require a daemon or provider. Archives omit repository-only tests and benches. Run `cargo test --workspace` from a standalone Git checkout for the full test suite.

Licensed under Apache-2.0 OR MIT; see the two license files in this package.

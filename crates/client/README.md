# pkcs11-proxy-ng-client

The Rust application entry point for connecting to a proxy daemon. `Pkcs11Client` exposes discovery, sessions, and operations; `types` and the named message parameter types are re-exported here. The [remote client example](examples/remote_client.rs) compiles with this package as its only direct project dependency: no separate `types` or `proto` dependency is needed.

The four user entry points are the daemon, Rust client, CLI, and C ABI shim. The audit, types, proto, and backend packages support those entry points.

Build from source with Rust 1.88 or newer and `protoc` installed. The Linux-first testing scope is one logical client in one trusted security domain per daemon/provider instance; a configured provider and daemon are needed for live operations. Crate archives contain source and build inputs, not prebuilt binaries, a provider module, or tokens. See the [project repository](https://github.com/mingulov/pkcs11-proxy-ng) for setup and release guidance.

Licensed under Apache-2.0 OR MIT; see the two license files in this package.

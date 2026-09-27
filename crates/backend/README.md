# pkcs11-proxy-ng-backend

Native provider loading and PKCS#11 calls for the daemon. This is an implementation crate, not a standalone token or HSM.

The four user entry points are the daemon, Rust client, CLI, and C ABI shim. The audit, types, proto, and backend packages support those entry points.

Build from source with Rust 1.88 or newer and `protoc` installed. The Linux-first testing scope is one logical client in one trusted security domain per daemon/provider instance; a configured provider and daemon are needed for live operations. Crate archives contain source and build inputs, not prebuilt binaries, a provider module, or tokens. See the [project repository](https://github.com/mingulov/pkcs11-proxy-ng) for setup and release guidance.

Licensed under Apache-2.0 OR MIT; see the two license files in this package.

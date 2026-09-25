pub mod pkcs11_proxy_ng {
    pub mod v1 {
        tonic::include_proto!("pkcs11_proxy_ng.v1");
    }
}

pub mod convert;
pub mod protected_decode;
pub mod secret_boundary;
pub mod version;

// W1-C8-07: build-time oneof cross-validation core, shared with build.rs via
// `#[path]`. Test-only in the crate: production code never calls it.
#[cfg(test)]
mod oneof_check;

// ADR-0013 redacted generated-message diagnostics, emitted by build.rs from
// secret-fields.toml + the protobuf schema (see build.rs). Defines
// `REDACTED_WIRE_MESSAGES` and the whole-message `TypeName([REDACTED])`
// `Debug` impls for every redacted wire message and oneof enum.
include!(concat!(env!("OUT_DIR"), "/redacted_debug_gen.rs"));

// T12 wipe closure, emitted by build.rs from secret-fields.toml + the
// protobuf schema. Defines `ZEROIZED_WIRE_MESSAGES`: every message deriving
// `Zeroize` (`ZeroizeOnDrop` too, except the prost-`Copy` members).
include!(concat!(env!("OUT_DIR"), "/zeroized_gen.rs"));

pub use pkcs11_proxy_ng::v1::pkcs11_proxy_client::Pkcs11ProxyClient;
pub use pkcs11_proxy_ng::v1::pkcs11_proxy_server::{Pkcs11Proxy, Pkcs11ProxyServer};
pub use pkcs11_proxy_ng::v1::*;

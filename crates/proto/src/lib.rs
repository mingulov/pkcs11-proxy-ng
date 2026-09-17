pub mod pkcs11_proxy_ng {
    pub mod v1 {
        tonic::include_proto!("pkcs11_proxy_ng.v1");
    }
}

pub mod convert;
pub mod secret_boundary;

// ADR-0013 redacted generated-message diagnostics, emitted by build.rs from
// secret-fields.toml + the protobuf schema (see build.rs). Defines
// `REDACTED_WIRE_MESSAGES` and the whole-message `TypeName([REDACTED])`
// `Debug` impls for every redacted wire message and oneof enum.
include!(concat!(env!("OUT_DIR"), "/redacted_debug_gen.rs"));

pub use pkcs11_proxy_ng::v1::pkcs11_proxy_client::Pkcs11ProxyClient;
pub use pkcs11_proxy_ng::v1::pkcs11_proxy_server::{Pkcs11Proxy, Pkcs11ProxyServer};
pub use pkcs11_proxy_ng::v1::*;

pub mod pkcs11_proxy_ng {
    pub mod v1 {
        tonic::include_proto!("pkcs11_proxy_ng.v1");
    }
}

pub mod convert;

pub use pkcs11_proxy_ng::v1::pkcs11_proxy_client::Pkcs11ProxyClient;
pub use pkcs11_proxy_ng::v1::pkcs11_proxy_server::{Pkcs11Proxy, Pkcs11ProxyServer};
pub use pkcs11_proxy_ng::v1::*;

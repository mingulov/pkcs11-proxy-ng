pub mod client;
pub mod error;
pub mod tls;

pub use pkcs11_proxy_ng_proto::convert::message_effects::MessageEffects;
pub use pkcs11_proxy_ng_proto::convert::message_params::{
    CcmMessageParams, GcmMessageParams, MessageParameter, Salsa20ChaCha20Poly1305MessageParams,
};
/// PKCS#11 value types used by the client API.
pub use pkcs11_proxy_ng_types as types;

pub use client::{
    BackendInterface, BackendProbe, ConnectError, ConnectTimeouts, DEFAULT_RPC_TIMEOUT,
    DeriveKeyMechanismOutResult, Pkcs11Client,
};
pub use error::{
    MessageCallError, MessageCallErrorOrigin, grpc_status_to_ck_rv, set_transport_failure_hook,
};

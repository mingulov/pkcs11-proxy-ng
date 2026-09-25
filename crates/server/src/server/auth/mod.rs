pub mod grant;
pub mod identity;
pub mod mtls;
// Note: there is intentionally no fd-based SO_PEERCRED helper module here.
// The live UDS auth flow gets peer credentials from tonic's
// `UdsConnectInfo.peer_cred` (see `request_identity.rs`); the former
// `peer_cred.rs` fd helpers had zero production callers and a stale
// "integration point" doc claim, so W1-C3-11 deleted them.
pub mod policy;
pub mod request_identity;
pub mod token_selector;

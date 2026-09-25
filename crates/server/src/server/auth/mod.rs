pub mod grant;
pub mod identity;
pub mod mtls;
// Linux-only: direct SO_PEERCRED extraction via nix. Intentionally absent on
// non-Linux targets; the live UDS auth flow uses tonic's UdsConnectInfo.peer_cred.
#[cfg(target_os = "linux")]
pub mod peer_cred;
pub mod policy;
pub mod request_identity;
pub mod token_selector;

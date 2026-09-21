use crate::config::{TcpAuthMode, UnixAuthMode};
#[cfg(unix)]
use tonic::transport::server::UdsConnectInfo;
use tonic::{Request, Status};

use super::identity::AuthenticatedIdentity;

/// Derive the authenticated identity for a request from its transport.
///
/// A Unix-socket connection carries tonic's [`UdsConnectInfo`] (populated with
/// the kernel's `SO_PEERCRED` peer credentials) in the request extensions; those
/// requests are authenticated via `unix_auth` (peer-cred — the local-IPC
/// equivalent of mutual auth; a Unix socket has no network to run mTLS over).
/// Every other connection is TCP and is authenticated via `tcp_auth` (mTLS).
/// `none` on either transport yields [`AuthenticatedIdentity::Unauthenticated`].
/// On non-Unix hosts the Unix transport does not exist (config validation
/// rejects `[listener.local]` there), so every request is TCP.
pub fn identity_from_request<T>(
    request: &Request<T>,
    tcp_auth: TcpAuthMode,
    unix_auth: UnixAuthMode,
) -> Result<AuthenticatedIdentity, Status> {
    #[cfg(unix)]
    if let Some(uds) = request.extensions().get::<UdsConnectInfo>() {
        return identity_from_uds(uds, unix_auth);
    }
    #[cfg(not(unix))]
    let _ = unix_auth;
    identity_from_tcp(request, tcp_auth)
}

#[cfg(unix)]
fn identity_from_uds(
    uds: &UdsConnectInfo,
    unix_auth: UnixAuthMode,
) -> Result<AuthenticatedIdentity, Status> {
    match unix_auth {
        UnixAuthMode::None => Ok(AuthenticatedIdentity::Unauthenticated),
        UnixAuthMode::PeerCred => {
            // Peer credentials are captured by tonic at accept time
            // (`UnixStream::peer_cred`, Linux SO_PEERCRED) and cannot be
            // forged by the peer. Its absence means the kernel did not provide
            // credentials — fail closed rather than fall through unauthenticated.
            // macOS: supported too — pinned tokio 1.50.0 implements
            // `get_peer_cred` for target_os = "macos" via getpeereid(2) +
            // LOCAL_PEEREPID (`impl_macos` in tokio's net/unix/ucred.rs), and
            // tonic sets `peer_cred: self.peer_cred().ok()`, so peer-cred mode
            // yields Some(UCred) there. `auth = "none"` on loopback and the
            // fail-closed None arm are unaffected on every target.
            let cred = uds.peer_cred.ok_or_else(|| {
                Status::unauthenticated("unix peer credentials unavailable (SO_PEERCRED)")
            })?;
            Ok(AuthenticatedIdentity::PeerCred { uid: cred.uid() })
        }
    }
}

fn identity_from_tcp<T>(
    request: &Request<T>,
    tcp_auth: TcpAuthMode,
) -> Result<AuthenticatedIdentity, Status> {
    match tcp_auth {
        TcpAuthMode::None => Ok(AuthenticatedIdentity::Unauthenticated),
        TcpAuthMode::Mtls => {
            let certs = request.peer_certs().ok_or_else(|| {
                Status::unauthenticated("mTLS listener request has no peer certificate")
            })?;
            let cert = certs.first().ok_or_else(|| {
                Status::unauthenticated("mTLS listener request has empty peer certificate chain")
            })?;
            let (issuer, subject, spki_sha256) = super::mtls::extract_identity(cert.as_ref())
                .map_err(|e| {
                    Status::unauthenticated(format!("invalid mTLS peer certificate: {e}"))
                })?;
            Ok(AuthenticatedIdentity::Mtls { issuer, subject, spki_sha256 })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::identity::AuthenticatedIdentity;
    use crate::config::{TcpAuthMode, UnixAuthMode};
    #[cfg(unix)]
    use tonic::transport::server::UdsConnectInfo;
    use tonic::{Code, Request};

    #[test]
    fn unauthenticated_tcp_returns_no_auth_identity() {
        let request = Request::new(());
        let identity =
            super::identity_from_request(&request, TcpAuthMode::None, UnixAuthMode::PeerCred)
                .unwrap();
        assert_eq!(identity.to_string(), "unauthenticated");
    }

    #[test]
    fn mtls_requires_peer_certificate() {
        let request = Request::new(());
        let err = super::identity_from_request(&request, TcpAuthMode::Mtls, UnixAuthMode::PeerCred)
            .unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[cfg(unix)]
    #[test]
    fn unix_none_auth_is_unauthenticated_even_with_uds_connect_info() {
        let mut request = Request::new(());
        // A UDS connection with no peer_cred captured (e.g. auth = none): the
        // presence of UdsConnectInfo routes to the unix path; `none` yields
        // Unauthenticated without requiring credentials.
        request.extensions_mut().insert(UdsConnectInfo { peer_addr: None, peer_cred: None });
        let identity =
            super::identity_from_request(&request, TcpAuthMode::Mtls, UnixAuthMode::None).unwrap();
        assert_eq!(identity.to_string(), "unauthenticated");
    }

    #[cfg(unix)]
    #[test]
    fn unix_peer_cred_without_credentials_fails_closed() {
        let mut request = Request::new(());
        request.extensions_mut().insert(UdsConnectInfo { peer_addr: None, peer_cred: None });
        // peer_cred mode but the kernel gave no credentials -> reject, do not
        // silently downgrade to Unauthenticated.
        let err = super::identity_from_request(&request, TcpAuthMode::None, UnixAuthMode::PeerCred)
            .unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    // W1-C3-31: the populated (Some) peer_cred arm, end to end through
    // identity_from_request. The UCred is kernel-issued (a socket pair's
    // peer_cred is our own uid); the expected uid is read independently
    // from the other end of the pair.
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_peer_cred_populated_yields_uid_identity() {
        let (a, b) = tokio::net::UnixStream::pair().expect("socket pair");
        let expected_uid = b.peer_cred().expect("peer cred").uid();
        let presented = a.peer_cred().expect("peer cred");
        assert_eq!(presented.uid(), expected_uid);
        let mut request = Request::new(());
        request
            .extensions_mut()
            .insert(UdsConnectInfo { peer_addr: None, peer_cred: Some(presented) });
        let identity =
            super::identity_from_request(&request, TcpAuthMode::None, UnixAuthMode::PeerCred)
                .unwrap();
        assert_eq!(identity, AuthenticatedIdentity::PeerCred { uid: expected_uid });
        assert_eq!(identity.to_string(), format!("uid={expected_uid}"));
    }
}

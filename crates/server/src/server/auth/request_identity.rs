use crate::config::{TcpAuthMode, UnixAuthMode};
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
pub fn identity_from_request<T>(
    request: &Request<T>,
    tcp_auth: TcpAuthMode,
    unix_auth: UnixAuthMode,
) -> Result<AuthenticatedIdentity, Status> {
    if let Some(uds) = request.extensions().get::<UdsConnectInfo>() {
        return identity_from_uds(uds, unix_auth);
    }
    identity_from_tcp(request, tcp_auth)
}

fn identity_from_uds(
    uds: &UdsConnectInfo,
    unix_auth: UnixAuthMode,
) -> Result<AuthenticatedIdentity, Status> {
    match unix_auth {
        UnixAuthMode::None => Ok(AuthenticatedIdentity::Unauthenticated),
        UnixAuthMode::PeerCred => {
            // SO_PEERCRED is captured by tonic at accept time and cannot be
            // forged by the peer. Its absence means the kernel did not provide
            // credentials — fail closed rather than fall through unauthenticated.
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
            let (issuer, subject) = super::mtls::extract_identity(cert.as_ref()).map_err(|e| {
                Status::unauthenticated(format!("invalid mTLS peer certificate: {e}"))
            })?;
            Ok(AuthenticatedIdentity::Mtls { issuer, subject })
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{TcpAuthMode, UnixAuthMode};
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
}

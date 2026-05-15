use crate::config::TcpAuthMode;
use tonic::{Request, Status};

use super::identity::AuthenticatedIdentity;

pub fn identity_from_request<T>(
    request: &Request<T>,
    auth: TcpAuthMode,
) -> Result<AuthenticatedIdentity, Status> {
    match auth {
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
    use crate::config::TcpAuthMode;
    use tonic::{Code, Request};

    #[test]
    fn unauthenticated_tcp_returns_no_auth_identity() {
        let request = Request::new(());

        let identity = super::identity_from_request(&request, TcpAuthMode::None).unwrap();

        assert_eq!(identity.to_string(), "unauthenticated");
    }

    #[test]
    fn mtls_requires_peer_certificate() {
        let request = Request::new(());

        let err = super::identity_from_request(&request, TcpAuthMode::Mtls).unwrap_err();

        assert_eq!(err.code(), Code::Unauthenticated);
    }
}

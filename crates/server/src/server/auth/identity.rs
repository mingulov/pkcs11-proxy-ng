#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AuthenticatedIdentity {
    /// Unix socket peer credentials: "uid=1000"
    PeerCred { uid: u32 },
    /// mTLS certificate identity: "x509:issuer=...;subject=..."
    Mtls { issuer: String, subject: String },
    /// No authentication (dev mode)
    Unauthenticated,
}

impl std::str::FromStr for AuthenticatedIdentity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "unauthenticated" {
            return Ok(Self::Unauthenticated);
        }

        if let Some(uid) = value.strip_prefix("uid=") {
            let uid = uid
                .parse::<u32>()
                .map_err(|_| format!("invalid peer credential identity '{value}'"))?;
            return Ok(Self::PeerCred { uid });
        }

        if let Some(rest) = value.strip_prefix("x509:issuer=") {
            let (issuer, subject) = rest
                .split_once(";subject=")
                .ok_or_else(|| format!("invalid mTLS identity '{value}'"))?;
            return Ok(Self::Mtls { issuer: issuer.into(), subject: subject.into() });
        }

        Err(format!("unknown authenticated identity format '{value}'"))
    }
}

impl std::fmt::Display for AuthenticatedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PeerCred { uid } => write!(f, "uid={uid}"),
            Self::Mtls { issuer, subject } => {
                write!(f, "x509:issuer={issuer};subject={subject}")
            }
            Self::Unauthenticated => write!(f, "unauthenticated"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_cred_display() {
        let id = AuthenticatedIdentity::PeerCred { uid: 1000 };
        assert_eq!(id.to_string(), "uid=1000");
    }

    #[test]
    fn mtls_display() {
        let id = AuthenticatedIdentity::Mtls {
            issuer: "CN=TestCA".into(),
            subject: "CN=client1".into(),
        };
        assert_eq!(id.to_string(), "x509:issuer=CN=TestCA;subject=CN=client1");
    }

    #[test]
    fn unauthenticated_display() {
        let id = AuthenticatedIdentity::Unauthenticated;
        assert_eq!(id.to_string(), "unauthenticated");
    }

    #[test]
    fn peer_cred_uid_zero_display() {
        // uid=0 is root; the display must not be ambiguous with any other format.
        let id = AuthenticatedIdentity::PeerCred { uid: 0 };
        assert_eq!(id.to_string(), "uid=0");
    }

    #[test]
    fn peer_cred_uid_max_display() {
        let id = AuthenticatedIdentity::PeerCred { uid: u32::MAX };
        assert_eq!(id.to_string(), format!("uid={}", u32::MAX));
    }

    #[test]
    fn mtls_empty_fields_display() {
        // Empty issuer/subject are valid (e.g. self-signed certs with no subject).
        let id = AuthenticatedIdentity::Mtls { issuer: "".into(), subject: "".into() };
        assert_eq!(id.to_string(), "x509:issuer=;subject=");
    }

    #[test]
    fn identity_equality_same_variant() {
        let a = AuthenticatedIdentity::PeerCred { uid: 42 };
        let b = AuthenticatedIdentity::PeerCred { uid: 42 };
        assert_eq!(a, b);
    }

    #[test]
    fn identity_inequality_different_uid() {
        let a = AuthenticatedIdentity::PeerCred { uid: 1 };
        let b = AuthenticatedIdentity::PeerCred { uid: 2 };
        assert_ne!(a, b);
    }

    #[test]
    fn identity_inequality_across_variants() {
        // The same display string must NOT be produced by two different variants.
        let a = AuthenticatedIdentity::Unauthenticated;
        let b = AuthenticatedIdentity::PeerCred { uid: 0 };
        assert_ne!(a, b);
        assert_ne!(a.to_string(), b.to_string());
    }

    #[test]
    fn identity_clone_is_equal() {
        let orig = AuthenticatedIdentity::Mtls { issuer: "CN=CA".into(), subject: "CN=srv".into() };
        assert_eq!(orig.clone(), orig);
    }

    #[test]
    fn policy_key_matches_display() {
        // The policy map is keyed on identity.to_string().
        // Verify the display is stable so policy lookups are consistent.
        let id = AuthenticatedIdentity::PeerCred { uid: 500 };
        assert_eq!(id.to_string(), "uid=500");

        let mtls = AuthenticatedIdentity::Mtls {
            issuer: "CN=Root CA".into(),
            subject: "CN=client".into(),
        };
        assert_eq!(mtls.to_string(), "x509:issuer=CN=Root CA;subject=CN=client");
    }

    #[test]
    fn parse_identity_round_trips_display() {
        let identities = [
            AuthenticatedIdentity::Unauthenticated,
            AuthenticatedIdentity::PeerCred { uid: 1000 },
            AuthenticatedIdentity::Mtls {
                issuer: "CN=Root CA".into(),
                subject: "CN=client".into(),
            },
        ];

        for identity in identities {
            assert_eq!(identity.to_string().parse::<AuthenticatedIdentity>().unwrap(), identity);
        }
    }

    #[test]
    fn parse_identity_rejects_unknown_format() {
        assert!("client1".parse::<AuthenticatedIdentity>().is_err());
    }
}

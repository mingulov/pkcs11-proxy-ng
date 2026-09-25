#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AuthenticatedIdentity {
    /// Unix socket peer credentials: "uid=1000"
    PeerCred { uid: u32 },
    /// mTLS certificate identity.
    ///
    /// Primary key (new): `"x509:spki=<hex-sha256>"` when `spki_sha256` is non-empty.
    /// Legacy key (transition): `"x509:issuer=...;subject=..."` when `spki_sha256` is empty.
    /// Enriched display (fresh from cert): `"x509:spki=<hash>;issuer=...;subject=..."`.
    Mtls { issuer: String, subject: String, spki_sha256: String },
    /// No authentication (dev mode)
    Unauthenticated,
}

/// Escape an mTLS identity component (issuer or subject DN) so the `;subject=`
/// join delimiter is unambiguous: a literal `\` becomes `\\` and a literal `;`
/// becomes `\;`. After escaping, the only *unescaped* `;` in the encoded
/// identity is the structural separator, which makes [`AuthenticatedIdentity`]'s
/// string form injective (G1: distinct DN pairs can no longer collide).
fn escape_identity_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            other => out.push(other),
        }
    }
    out
}

/// Inverse of [`escape_identity_component`].
fn unescape_identity_component(value: &str) -> Result<String, String> {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some(';') => out.push(';'),
                Some(other) => return Err(format!("invalid escape '\\{other}' in mTLS identity")),
                None => return Err("trailing escape in mTLS identity".into()),
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// Split an escaped `issuer;subject=subject` body at the structural separator —
/// the first `;` preceded by an even number of backslashes (i.e. unescaped),
/// which must be immediately followed by `subject=`. Returns the still-escaped
/// issuer and subject halves, or `None` if the body is malformed/ambiguous.
fn split_escaped_identity_body(rest: &str) -> Option<(&str, &str)> {
    let bytes = rest.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b';' {
            continue;
        }
        let mut backslashes = 0;
        let mut j = i;
        while j > 0 && bytes[j - 1] == b'\\' {
            backslashes += 1;
            j -= 1;
        }
        if backslashes % 2 != 0 {
            continue; // this ';' is escaped — part of a value
        }
        // ';' is ASCII, so byte index i is a char boundary.
        return rest[i..].strip_prefix(";subject=").map(|subject| (&rest[..i], subject));
    }
    None
}

impl AuthenticatedIdentity {
    /// Returns the legacy DN-keyed identity string (`x509:issuer=...;subject=...`) when
    /// the identity carries a non-empty issuer or subject DN.
    ///
    /// Used by the policy engine for dual-accept fallback: during the transition from DN-keyed
    /// to SPKI-keyed policy entries, existing `x509:issuer=...;subject=...` policy entries
    /// still authorize clients whose freshly-extracted identity carries both SPKI and DN.
    ///
    /// Returns `None` for SPKI-only identities (both DN components empty), PeerCred, and
    /// Unauthenticated — those have no meaningful legacy DN key to look up.
    pub fn legacy_dn_key(&self) -> Option<String> {
        match self {
            Self::Mtls { issuer, subject, .. } if !issuer.is_empty() || !subject.is_empty() => {
                Some(format!(
                    "x509:issuer={};subject={}",
                    escape_identity_component(issuer),
                    escape_identity_component(subject)
                ))
            }
            _ => None,
        }
    }
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

        // New SPKI-keyed form: "x509:spki=<hash>" or "x509:spki=<hash>;issuer=...;subject=..."
        if let Some(rest) = value.strip_prefix("x509:spki=") {
            // Check for enriched form: contains ";issuer="
            if let Some(semi_pos) = rest.find(';') {
                // Enriched form: hash;issuer=<escaped_issuer>;subject=<escaped_subject>
                let hash = &rest[..semi_pos];
                let after_semi = &rest[semi_pos + 1..];
                let dn_body = after_semi
                    .strip_prefix("issuer=")
                    .ok_or_else(|| format!("invalid enriched mTLS identity '{value}'"))?;
                let (esc_issuer, esc_subject) = split_escaped_identity_body(dn_body)
                    .ok_or_else(|| format!("invalid enriched mTLS identity '{value}'"))?;
                return Ok(Self::Mtls {
                    spki_sha256: hash.to_string(),
                    issuer: unescape_identity_component(esc_issuer)?,
                    subject: unescape_identity_component(esc_subject)?,
                });
            }
            // Short form: "x509:spki=<hash>" — no DN components
            return Ok(Self::Mtls {
                spki_sha256: rest.to_string(),
                issuer: "".into(),
                subject: "".into(),
            });
        }

        // Legacy DN form: "x509:issuer=<escaped_issuer>;subject=<escaped_subject>"
        if let Some(rest) = value.strip_prefix("x509:issuer=") {
            let (issuer, subject) = split_escaped_identity_body(rest)
                .ok_or_else(|| format!("invalid mTLS identity '{value}'"))?;
            return Ok(Self::Mtls {
                issuer: unescape_identity_component(issuer)?,
                subject: unescape_identity_component(subject)?,
                spki_sha256: "".into(),
            });
        }

        Err(format!("unknown authenticated identity format '{value}'"))
    }
}

impl std::fmt::Display for AuthenticatedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PeerCred { uid } => write!(f, "uid={uid}"),
            Self::Mtls { issuer, subject, spki_sha256 } => {
                if spki_sha256.is_empty() {
                    // Legacy identity (no SPKI): use the old DN-keyed format for backward compat.
                    // This is also the display for identities parsed from legacy stored strings.
                    write!(
                        f,
                        "x509:issuer={};subject={}",
                        escape_identity_component(issuer),
                        escape_identity_component(subject),
                    )
                } else if issuer.is_empty() && subject.is_empty() {
                    // SPKI-only: short form
                    write!(f, "x509:spki={spki_sha256}")
                } else {
                    // Enriched: SPKI primary key + DN for human readability
                    write!(
                        f,
                        "x509:spki={spki_sha256};issuer={};subject={}",
                        escape_identity_component(issuer),
                        escape_identity_component(subject),
                    )
                }
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
            spki_sha256: "".into(),
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
        // Empty issuer/subject with empty SPKI: legacy format.
        let id = AuthenticatedIdentity::Mtls {
            issuer: "".into(),
            subject: "".into(),
            spki_sha256: "".into(),
        };
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
        let orig = AuthenticatedIdentity::Mtls {
            issuer: "CN=CA".into(),
            subject: "CN=srv".into(),
            spki_sha256: "".into(),
        };
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
            spki_sha256: "".into(),
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
                spki_sha256: "".into(),
            },
            // SPKI-only form
            AuthenticatedIdentity::Mtls {
                issuer: "".into(),
                subject: "".into(),
                spki_sha256: "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678"
                    .into(),
            },
            // Enriched SPKI+DN form
            AuthenticatedIdentity::Mtls {
                issuer: "CN=Root CA".into(),
                subject: "CN=client".into(),
                spki_sha256: "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678"
                    .into(),
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

    // --- G1: the identity key must be injective and round-trip exactly ---

    #[test]
    fn mtls_identity_with_join_delimiter_in_issuer_round_trips() {
        // An issuer DN whose text contains the literal join delimiter must not
        // be confused with the issuer/subject boundary.
        let id = AuthenticatedIdentity::Mtls {
            issuer: "CN=x;subject=evil".into(),
            subject: "CN=client".into(),
            spki_sha256: "".into(),
        };
        assert_eq!(id.to_string().parse::<AuthenticatedIdentity>().unwrap(), id);
    }

    #[test]
    fn distinct_dn_pairs_never_collide_on_the_same_key() {
        // These two distinct certificate identities previously produced the
        // SAME string ("...issuer=A;subject=B;subject=C"), letting one match the
        // other's policy entry / spoof it past the A2 ownership check.
        let a = AuthenticatedIdentity::Mtls {
            issuer: "A;subject=B".into(),
            subject: "C".into(),
            spki_sha256: "".into(),
        };
        let b = AuthenticatedIdentity::Mtls {
            issuer: "A".into(),
            subject: "B;subject=C".into(),
            spki_sha256: "".into(),
        };
        assert_ne!(a.to_string(), b.to_string());
        assert_eq!(a.to_string().parse::<AuthenticatedIdentity>().unwrap(), a);
        assert_eq!(b.to_string().parse::<AuthenticatedIdentity>().unwrap(), b);
    }

    #[test]
    fn mtls_identity_with_backslash_round_trips() {
        let id = AuthenticatedIdentity::Mtls {
            issuer: "CN=a\\b".into(),
            subject: "CN=c\\;d".into(),
            spki_sha256: "".into(),
        };
        assert_eq!(id.to_string().parse::<AuthenticatedIdentity>().unwrap(), id);
    }

    #[test]
    fn mtls_identity_with_equals_and_plus_round_trips() {
        // '=' and '+' appear in multi-valued RDNs; they are not delimiters here
        // and must round-trip untouched.
        let id = AuthenticatedIdentity::Mtls {
            issuer: "CN=a+OU=b".into(),
            subject: "CN=c=d".into(),
            spki_sha256: "".into(),
        };
        assert_eq!(id.to_string().parse::<AuthenticatedIdentity>().unwrap(), id);
    }

    #[test]
    fn parse_rejects_mtls_with_stray_unescaped_delimiter() {
        // A bare unescaped ';' that is not the structural ";subject=" is
        // ambiguous and must be rejected rather than silently mis-parsed.
        assert!("x509:issuer=A;B".parse::<AuthenticatedIdentity>().is_err());
    }

    // --- SPKI identity tests ---

    #[test]
    fn spki_identity_display_starts_with_x509_spki() {
        let id = AuthenticatedIdentity::Mtls {
            issuer: "CN=Root CA".into(),
            subject: "CN=client".into(),
            spki_sha256: "aabbccddeeff0011aabbccddeeff001122334455667788990011223344556677".into(),
        };
        assert!(id.to_string().starts_with("x509:spki="), "display: {id}");
    }

    #[test]
    fn spki_only_identity_round_trips() {
        let id = AuthenticatedIdentity::Mtls {
            issuer: "".into(),
            subject: "".into(),
            spki_sha256: "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678".into(),
        };
        let s = id.to_string();
        assert_eq!(s, "x509:spki=deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678");
        assert_eq!(s.parse::<AuthenticatedIdentity>().unwrap(), id);
    }

    #[test]
    fn enriched_spki_identity_round_trips() {
        let id = AuthenticatedIdentity::Mtls {
            issuer: "CN=Root CA".into(),
            subject: "CN=client".into(),
            spki_sha256: "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678".into(),
        };
        let s = id.to_string();
        assert!(s.starts_with("x509:spki="), "display: {s}");
        assert!(s.contains(";issuer="), "display: {s}");
        assert!(s.contains(";subject="), "display: {s}");
        assert_eq!(s.parse::<AuthenticatedIdentity>().unwrap(), id);
    }

    #[test]
    fn legacy_dn_key_returns_none_for_empty_dn() {
        let id = AuthenticatedIdentity::Mtls {
            issuer: "".into(),
            subject: "".into(),
            spki_sha256: "deadbeef".into(),
        };
        assert_eq!(id.legacy_dn_key(), None);
    }

    #[test]
    fn legacy_dn_key_returns_dn_form_for_non_empty_dn() {
        let id = AuthenticatedIdentity::Mtls {
            issuer: "CN=Root CA".into(),
            subject: "CN=client".into(),
            spki_sha256: "deadbeef".into(),
        };
        assert_eq!(
            id.legacy_dn_key(),
            Some("x509:issuer=CN=Root CA;subject=CN=client".to_string())
        );
    }
}

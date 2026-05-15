use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use std::os::fd::AsFd;

/// Unix socket peer credential extraction result.
///
/// Contains UID, GID, and PID from `SO_PEERCRED`. GID is available for
/// logging and future policy extensions but is not a Phase 1 policy key
/// (ADR-0005 §1). PID is useful for diagnostics.
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}

/// Extract the UID of the peer process from Unix socket credentials.
pub fn extract_peer_uid<F: AsFd>(fd: &F) -> Result<u32, String> {
    let cred = extract_peer_cred(fd)?;
    Ok(cred.uid)
}

/// Extract full peer credentials (UID, GID, PID) from a Unix socket.
///
/// Uses `SO_PEERCRED` (Linux-specific). The credentials are set by the
/// kernel at connect time and cannot be forged by the peer process.
///
/// # Socket permission model
///
/// The daemon's Unix socket file permissions control which local users can
/// connect. Recommended deployment patterns:
///
/// - **Single-user dev:** socket owned by the developer, mode 0600.
///   Only the developer's UID can connect.
/// - **Service user:** daemon runs as a dedicated service user, socket
///   at `/run/pkcs11-proxy/pkcs11-proxy-ng.sock`, owned by the service user,
///   group set to a shared group (e.g. `pkcs11`), mode 0660.
///   Group members can connect; others are denied by the filesystem.
/// - **System-wide:** socket mode 0666 with `auth = "peer_cred"` and
///   policy entries controlling per-UID access. Filesystem allows
///   connection; policy controls token access.
///
/// In all cases, `SO_PEERCRED` provides the connecting process's UID
/// which the daemon maps to `AuthenticatedIdentity::PeerCred { uid }`.
pub fn extract_peer_cred<F: AsFd>(fd: &F) -> Result<PeerCred, String> {
    let cred = getsockopt(fd, PeerCredentials).map_err(|e| format!("SO_PEERCRED failed: {e}"))?;
    Ok(PeerCred { uid: cred.uid(), gid: cred.gid(), pid: cred.pid() })
}

/// Build an `AuthenticatedIdentity` from a Unix socket file descriptor.
///
/// This is the integration point between transport-level peer credentials
/// and the daemon's identity/policy model.
pub fn identity_from_fd<F: AsFd>(fd: &F) -> Result<super::identity::AuthenticatedIdentity, String> {
    let cred = extract_peer_cred(fd)?;
    Ok(super::identity::AuthenticatedIdentity::PeerCred { uid: cred.uid })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

    fn unix_pair() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
        socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::empty())
            .expect("socketpair failed")
    }

    #[test]
    fn peer_cred_succeeds_on_unix_socket() {
        let (fd1, _fd2) = unix_pair();
        assert!(extract_peer_uid(&fd1).is_ok());
    }

    #[test]
    fn peer_cred_symmetric_both_ends() {
        let (fd1, fd2) = unix_pair();
        let uid1 = extract_peer_uid(&fd1).expect("fd1 SO_PEERCRED failed");
        let uid2 = extract_peer_uid(&fd2).expect("fd2 SO_PEERCRED failed");
        assert_eq!(uid1, uid2, "symmetric socketpair must yield same peer UID");
    }

    #[test]
    fn peer_cred_uid_is_nonzero_or_zero_not_sentinel() {
        let (fd1, _fd2) = unix_pair();
        let uid = extract_peer_uid(&fd1).expect("SO_PEERCRED failed");
        let _ = uid;
    }

    // --- Item 87: Unix peer-credential and socket-permission model ---

    #[test]
    fn full_peer_cred_extraction() {
        let (fd1, _fd2) = unix_pair();
        let cred = extract_peer_cred(&fd1).unwrap();
        // Same-process socketpair: UID and GID must match our process
        let my_uid = nix::unistd::getuid().as_raw();
        let my_gid = nix::unistd::getgid().as_raw();
        assert_eq!(cred.uid, my_uid, "peer UID must match process UID");
        assert_eq!(cred.gid, my_gid, "peer GID must match process GID");
        assert!(cred.pid > 0, "PID must be positive: {}", cred.pid);
    }

    #[test]
    fn peer_cred_pid_matches_current_process() {
        let (fd1, _fd2) = unix_pair();
        let cred = extract_peer_cred(&fd1).unwrap();
        let my_pid = std::process::id() as i32;
        assert_eq!(cred.pid, my_pid, "peer PID must match current process");
    }

    #[test]
    fn identity_from_fd_produces_peer_cred_variant() {
        let (fd1, _fd2) = unix_pair();
        let id = identity_from_fd(&fd1).unwrap();
        let my_uid = nix::unistd::getuid().as_raw();
        match id {
            super::super::identity::AuthenticatedIdentity::PeerCred { uid } => {
                assert_eq!(uid, my_uid);
            }
            other => panic!("expected PeerCred, got {:?}", other),
        }
    }

    #[test]
    fn identity_from_fd_display_matches_policy_key_format() {
        let (fd1, _fd2) = unix_pair();
        let id = identity_from_fd(&fd1).unwrap();
        let display = id.to_string();
        assert!(display.starts_with("uid="), "display should be uid=N format: {display}");
    }

    #[test]
    fn peer_cred_to_policy_integration() {
        // End-to-end: extract identity from socket → match against policy.
        use super::super::policy::{TokenAccess, TokenPolicy, TokenSelector};
        use std::collections::HashMap;

        let (fd1, _fd2) = unix_pair();
        let id = identity_from_fd(&fd1).unwrap();
        let policy_key = id.to_string();

        // Build a policy that allows this UID to access "my-hsm"
        let mut rules = HashMap::new();
        rules
            .insert(policy_key, TokenAccess::Specific(vec![TokenSelector::Label("my-hsm".into())]));
        let policy = TokenPolicy { rules, allow_all_authenticated: false };

        assert!(
            policy.allows(&id, "my-hsm", "any-serial"),
            "identity from socket should match policy"
        );
        assert!(
            !policy.allows(&id, "other-hsm", "any-serial"),
            "identity should be denied for other tokens"
        );
    }

    #[test]
    fn peer_cred_gid_symmetric() {
        // Both ends of a socketpair report the same GID.
        let (fd1, fd2) = unix_pair();
        let cred1 = extract_peer_cred(&fd1).unwrap();
        let cred2 = extract_peer_cred(&fd2).unwrap();
        assert_eq!(cred1.gid, cred2.gid, "GID must be symmetric");
    }

    #[test]
    fn peer_cred_returns_kernel_set_credentials() {
        // SO_PEERCRED credentials are set by the kernel at connect time
        // and cannot be forged by the peer. Verify that the returned
        // credentials match the current process identity.
        let (fd1, _fd2) = unix_pair();
        let cred = extract_peer_cred(&fd1).unwrap();
        let my_uid = nix::unistd::getuid().as_raw();
        let my_pid = std::process::id() as i32;
        assert_eq!(cred.uid, my_uid);
        assert_eq!(cred.pid, my_pid);
    }

    #[test]
    fn multi_user_policy_isolation() {
        // Simulate two users connecting: uid=1000 and uid=2000.
        // Each should only see their own tokens.
        use super::super::identity::AuthenticatedIdentity;
        use super::super::policy::{TokenAccess, TokenPolicy, TokenSelector};
        use std::collections::HashMap;

        let mut rules = HashMap::new();
        rules.insert(
            "uid=1000".into(),
            TokenAccess::Specific(vec![TokenSelector::Label("user1-token".into())]),
        );
        rules.insert(
            "uid=2000".into(),
            TokenAccess::Specific(vec![TokenSelector::Label("user2-token".into())]),
        );
        let policy = TokenPolicy { rules, allow_all_authenticated: false };

        let user1 = AuthenticatedIdentity::PeerCred { uid: 1000 };
        let user2 = AuthenticatedIdentity::PeerCred { uid: 2000 };

        // user1 can only access user1-token
        assert!(policy.allows(&user1, "user1-token", "any"));
        assert!(!policy.allows(&user1, "user2-token", "any"));

        // user2 can only access user2-token
        assert!(policy.allows(&user2, "user2-token", "any"));
        assert!(!policy.allows(&user2, "user1-token", "any"));
    }
}

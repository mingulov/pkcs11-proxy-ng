use crate::slot::CkSlotId;

/// General-purpose PKCS#11 flags (CK_FLAGS). Used where no more specific flag
/// newtype applies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CkFlags(pub u64);

/// Virtual session handle — scoped to logical client instance (ADR-0002 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CkSessionHandle(pub u64);

/// PKCS#11 session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum CkSessionState {
    RoPublic = 0,
    RoUser = 1,
    RwPublic = 2,
    RwUser = 3,
    RwSo = 4,
}

/// Session flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CkSessionFlags(pub u64);

impl CkSessionFlags {
    pub const RW_SESSION: u64 = 0x00000002;
    pub const SERIAL_SESSION: u64 = 0x00000004;

    pub fn is_rw(self) -> bool {
        self.0 & Self::RW_SESSION != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkSessionInfo {
    pub slot_id: CkSlotId,
    pub state: CkSessionState,
    pub flags: CkSessionFlags,
    pub device_error: u64,
}

/// PKCS#11 user type for C_Login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum CkUserType {
    So = 0,
    User = 1,
    ContextSpecific = 2,
}

impl CkUserType {
    pub fn from_raw(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::So),
            1 => Some(Self::User),
            2 => Some(Self::ContextSpecific),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_flags_rw() {
        let flags = CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION);
        assert!(flags.is_rw());
    }

    #[test]
    fn user_type_round_trip() {
        assert_eq!(CkUserType::from_raw(1), Some(CkUserType::User));
        assert_eq!(CkUserType::from_raw(99), None);
    }

    // ---- session/login state matrix (Item 61) ----

    #[test]
    fn all_session_states_have_correct_discriminants() {
        // PKCS#11 §5.4 table: raw values must match the spec.
        assert_eq!(CkSessionState::RoPublic as u64, 0);
        assert_eq!(CkSessionState::RoUser as u64, 1);
        assert_eq!(CkSessionState::RwPublic as u64, 2);
        assert_eq!(CkSessionState::RwUser as u64, 3);
        assert_eq!(CkSessionState::RwSo as u64, 4);
    }

    #[test]
    fn session_flags_ro_not_rw() {
        // SERIAL_SESSION alone does not make a session RW.
        let ro_flags = CkSessionFlags(CkSessionFlags::SERIAL_SESSION);
        assert!(!ro_flags.is_rw());
    }

    #[test]
    fn session_flags_default_not_rw() {
        assert!(!CkSessionFlags::default().is_rw());
    }

    #[test]
    fn user_type_so_from_raw() {
        assert_eq!(CkUserType::from_raw(0), Some(CkUserType::So));
    }

    #[test]
    fn user_type_context_specific_from_raw() {
        assert_eq!(CkUserType::from_raw(2), Some(CkUserType::ContextSpecific));
    }

    #[test]
    fn user_type_invalid_raw_returns_none() {
        // Values 3-9 and above are not defined in PKCS#11.
        for v in [3u64, 4, 9, 99, u64::MAX] {
            assert_eq!(CkUserType::from_raw(v), None, "from_raw({v}) should be None");
        }
    }

    #[test]
    fn session_info_fields_preserved() {
        let info = CkSessionInfo {
            slot_id: crate::slot::CkSlotId(7),
            state: CkSessionState::RwUser,
            flags: CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION),
            device_error: 42,
        };
        assert_eq!(info.slot_id.0, 7);
        assert_eq!(info.state, CkSessionState::RwUser);
        assert!(info.flags.is_rw());
        assert_eq!(info.device_error, 42);
    }
}

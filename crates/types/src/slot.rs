/// Virtual slot ID — daemon-assigned, never the backend's raw slot ID.
/// The daemon maps virtual → backend slot IDs in a SlotMap (Task 4.2).
/// Not stable across daemon restarts (ADR-0002 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CkSlotId(pub u64);

/// Flags for CK_SLOT_INFO.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CkSlotFlags(pub u64);

impl CkSlotFlags {
    pub const TOKEN_PRESENT: Self = Self(0x01);
    pub const REMOVABLE_DEVICE: Self = Self(0x02);
    pub const HW_SLOT: Self = Self(0x04);

    pub fn token_present(self) -> bool {
        self.0 & Self::TOKEN_PRESENT.0 != 0
    }
}

impl std::ops::BitOr for CkSlotFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for CkSlotFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkSlotInfo {
    pub slot_description: String,
    pub manufacturer_id: String,
    pub flags: CkSlotFlags,
    pub hardware_version: (u8, u8),
    pub firmware_version: (u8, u8),
}

/// Flags for CK_TOKEN_INFO.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CkTokenFlags(pub u64);

impl CkTokenFlags {
    // Standard CK_TOKEN_INFO bits (CKF_* values from the OASIS 2.40
    // pkcs11t.h, unchanged through PKCS#11 v3.x).
    pub const RNG: Self = Self(0x0000_0001);
    pub const WRITE_PROTECTED: Self = Self(0x0000_0002);
    pub const LOGIN_REQUIRED: Self = Self(0x0000_0004);
    pub const USER_PIN_INITIALIZED: Self = Self(0x0000_0008);
    pub const RESTORE_KEY_NOT_NEEDED: Self = Self(0x0000_0020);
    pub const CLOCK_ON_TOKEN: Self = Self(0x0000_0040);
    pub const PROTECTED_AUTHENTICATION_PATH: Self = Self(0x0000_0100);
    pub const DUAL_CRYPTO_OPERATIONS: Self = Self(0x0000_0200);
    pub const TOKEN_INITIALIZED: Self = Self(0x0000_0400);
    pub const SECONDARY_AUTHENTICATION: Self = Self(0x0000_0800);
    pub const USER_PIN_COUNT_LOW: Self = Self(0x0001_0000);
    pub const USER_PIN_FINAL_TRY: Self = Self(0x0002_0000);
    pub const USER_PIN_LOCKED: Self = Self(0x0004_0000);
    pub const USER_PIN_TO_BE_CHANGED: Self = Self(0x0008_0000);
    pub const SO_PIN_COUNT_LOW: Self = Self(0x0010_0000);
    pub const SO_PIN_FINAL_TRY: Self = Self(0x0020_0000);
    pub const SO_PIN_LOCKED: Self = Self(0x0040_0000);
    pub const SO_PIN_TO_BE_CHANGED: Self = Self(0x0080_0000);
    pub const ERROR_STATE: Self = Self(0x0100_0000);

    pub fn login_required(self) -> bool {
        self.0 & Self::LOGIN_REQUIRED.0 != 0
    }
    pub fn token_initialized(self) -> bool {
        self.0 & Self::TOKEN_INITIALIZED.0 != 0
    }
}

impl std::ops::BitOr for CkTokenFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for CkTokenFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkTokenInfo {
    pub label: String,
    pub manufacturer_id: String,
    pub model: String,
    pub serial_number: String,
    pub flags: CkTokenFlags,
    pub max_session_count: u64,
    pub session_count: u64,
    pub max_rw_session_count: u64,
    pub rw_session_count: u64,
    pub max_pin_len: u64,
    pub min_pin_len: u64,
    pub total_public_memory: u64,
    pub free_public_memory: u64,
    pub total_private_memory: u64,
    pub free_private_memory: u64,
    pub hardware_version: (u8, u8),
    pub firmware_version: (u8, u8),
    pub utc_time: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_flags_token_present() {
        let flags = CkSlotFlags::TOKEN_PRESENT | CkSlotFlags::HW_SLOT;
        assert!(flags.token_present());
    }

    #[test]
    fn slot_id_equality() {
        assert_eq!(CkSlotId(1), CkSlotId(1));
        assert_ne!(CkSlotId(1), CkSlotId(2));
    }

    // W1-C9-08: every standard CK_TOKEN_INFO bit has a named const (values
    // from the OASIS 2.40 pkcs11t.h CKF_* table); callers never hand-compose
    // literals like CkTokenFlags(0x0404).
    #[test]
    fn w1_c9_08_token_flags_name_standard_bits() {
        assert_eq!(CkTokenFlags::RNG, CkTokenFlags(0x0000_0001));
        assert_eq!(CkTokenFlags::WRITE_PROTECTED, CkTokenFlags(0x0000_0002));
        assert_eq!(CkTokenFlags::LOGIN_REQUIRED, CkTokenFlags(0x0000_0004));
        assert_eq!(CkTokenFlags::USER_PIN_INITIALIZED, CkTokenFlags(0x0000_0008));
        assert_eq!(CkTokenFlags::RESTORE_KEY_NOT_NEEDED, CkTokenFlags(0x0000_0020));
        assert_eq!(CkTokenFlags::CLOCK_ON_TOKEN, CkTokenFlags(0x0000_0040));
        assert_eq!(CkTokenFlags::PROTECTED_AUTHENTICATION_PATH, CkTokenFlags(0x0000_0100));
        assert_eq!(CkTokenFlags::DUAL_CRYPTO_OPERATIONS, CkTokenFlags(0x0000_0200));
        assert_eq!(CkTokenFlags::TOKEN_INITIALIZED, CkTokenFlags(0x0000_0400));
        assert_eq!(CkTokenFlags::SECONDARY_AUTHENTICATION, CkTokenFlags(0x0000_0800));
        assert_eq!(CkTokenFlags::USER_PIN_COUNT_LOW, CkTokenFlags(0x0001_0000));
        assert_eq!(CkTokenFlags::USER_PIN_FINAL_TRY, CkTokenFlags(0x0002_0000));
        assert_eq!(CkTokenFlags::USER_PIN_LOCKED, CkTokenFlags(0x0004_0000));
        assert_eq!(CkTokenFlags::USER_PIN_TO_BE_CHANGED, CkTokenFlags(0x0008_0000));
        assert_eq!(CkTokenFlags::SO_PIN_COUNT_LOW, CkTokenFlags(0x0010_0000));
        assert_eq!(CkTokenFlags::SO_PIN_FINAL_TRY, CkTokenFlags(0x0020_0000));
        assert_eq!(CkTokenFlags::SO_PIN_LOCKED, CkTokenFlags(0x0040_0000));
        assert_eq!(CkTokenFlags::SO_PIN_TO_BE_CHANGED, CkTokenFlags(0x0080_0000));
        assert_eq!(CkTokenFlags::ERROR_STATE, CkTokenFlags(0x0100_0000));
        // The old hand-composed literal is exactly the named combination.
        assert_eq!(
            CkTokenFlags::TOKEN_INITIALIZED | CkTokenFlags::LOGIN_REQUIRED,
            CkTokenFlags(0x0404)
        );
    }

    // W1-C9-13: slot/token flag consts are Self-typed (CkRv/CkAttributeType/
    // CkMechanismType convention) and combine with `|`.
    #[test]
    fn w1_c9_13_slot_token_flag_consts_are_self_typed() {
        let slot: CkSlotFlags = CkSlotFlags::TOKEN_PRESENT;
        assert_eq!(slot.0, 0x01);
        let combined: CkSlotFlags = CkSlotFlags::TOKEN_PRESENT | CkSlotFlags::HW_SLOT;
        assert_eq!(combined.0, 0x05);
        let token: CkTokenFlags = CkTokenFlags::LOGIN_REQUIRED;
        assert_eq!(token.0, 0x04);
        let mut acc = CkSlotFlags::HW_SLOT;
        acc |= CkSlotFlags::TOKEN_PRESENT;
        assert_eq!(acc.0, 0x05);
    }
}

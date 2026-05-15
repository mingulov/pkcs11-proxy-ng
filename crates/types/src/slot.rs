/// Virtual slot ID — daemon-assigned, never the backend's raw slot ID.
/// The daemon maps virtual → backend slot IDs in a SlotMap (Task 4.2).
/// Not stable across daemon restarts (ADR-0002 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CkSlotId(pub u64);

/// Flags for CK_SLOT_INFO.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CkSlotFlags(pub u64);

impl CkSlotFlags {
    pub const TOKEN_PRESENT: u64 = 0x01;
    pub const REMOVABLE_DEVICE: u64 = 0x02;
    pub const HW_SLOT: u64 = 0x04;

    pub fn token_present(self) -> bool {
        self.0 & Self::TOKEN_PRESENT != 0
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
    pub const LOGIN_REQUIRED: u64 = 0x00000004;
    pub const TOKEN_INITIALIZED: u64 = 0x00000400;

    pub fn login_required(self) -> bool {
        self.0 & Self::LOGIN_REQUIRED != 0
    }
    pub fn token_initialized(self) -> bool {
        self.0 & Self::TOKEN_INITIALIZED != 0
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
        let flags = CkSlotFlags(CkSlotFlags::TOKEN_PRESENT | CkSlotFlags::HW_SLOT);
        assert!(flags.token_present());
    }

    #[test]
    fn slot_id_equality() {
        assert_eq!(CkSlotId(1), CkSlotId(1));
        assert_ne!(CkSlotId(1), CkSlotId(2));
    }
}

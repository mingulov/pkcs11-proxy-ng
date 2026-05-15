use crate::pkcs11_proxy_ng::v1 as v1_proto;
use pkcs11_proxy_ng_types::{CkInfo, CkSlotFlags, CkSlotInfo, CkTokenFlags, CkTokenInfo};

impl From<&CkSlotInfo> for v1_proto::SlotInfo {
    fn from(s: &CkSlotInfo) -> Self {
        v1_proto::SlotInfo {
            slot_description: s.slot_description.clone(),
            manufacturer_id: s.manufacturer_id.clone(),
            flags: s.flags.0,
            hardware_version_major: s.hardware_version.0 as u32,
            hardware_version_minor: s.hardware_version.1 as u32,
            firmware_version_major: s.firmware_version.0 as u32,
            firmware_version_minor: s.firmware_version.1 as u32,
        }
    }
}

impl From<&v1_proto::SlotInfo> for CkSlotInfo {
    fn from(s: &v1_proto::SlotInfo) -> Self {
        CkSlotInfo {
            slot_description: s.slot_description.clone(),
            manufacturer_id: s.manufacturer_id.clone(),
            flags: CkSlotFlags(s.flags),
            hardware_version: (s.hardware_version_major as u8, s.hardware_version_minor as u8),
            firmware_version: (s.firmware_version_major as u8, s.firmware_version_minor as u8),
        }
    }
}

impl From<&CkTokenInfo> for v1_proto::TokenInfo {
    fn from(t: &CkTokenInfo) -> Self {
        v1_proto::TokenInfo {
            label: t.label.clone(),
            manufacturer_id: t.manufacturer_id.clone(),
            model: t.model.clone(),
            serial_number: t.serial_number.clone(),
            flags: t.flags.0,
            max_session_count: t.max_session_count,
            session_count: t.session_count,
            max_rw_session_count: t.max_rw_session_count,
            rw_session_count: t.rw_session_count,
            max_pin_len: t.max_pin_len,
            min_pin_len: t.min_pin_len,
            total_public_memory: t.total_public_memory,
            free_public_memory: t.free_public_memory,
            total_private_memory: t.total_private_memory,
            free_private_memory: t.free_private_memory,
            hardware_version_major: t.hardware_version.0 as u32,
            hardware_version_minor: t.hardware_version.1 as u32,
            firmware_version_major: t.firmware_version.0 as u32,
            firmware_version_minor: t.firmware_version.1 as u32,
            utc_time: t.utc_time.clone(),
        }
    }
}

impl From<&v1_proto::TokenInfo> for CkTokenInfo {
    fn from(t: &v1_proto::TokenInfo) -> Self {
        CkTokenInfo {
            label: t.label.clone(),
            manufacturer_id: t.manufacturer_id.clone(),
            model: t.model.clone(),
            serial_number: t.serial_number.clone(),
            flags: CkTokenFlags(t.flags),
            max_session_count: t.max_session_count,
            session_count: t.session_count,
            max_rw_session_count: t.max_rw_session_count,
            rw_session_count: t.rw_session_count,
            max_pin_len: t.max_pin_len,
            min_pin_len: t.min_pin_len,
            total_public_memory: t.total_public_memory,
            free_public_memory: t.free_public_memory,
            total_private_memory: t.total_private_memory,
            free_private_memory: t.free_private_memory,
            hardware_version: (t.hardware_version_major as u8, t.hardware_version_minor as u8),
            firmware_version: (t.firmware_version_major as u8, t.firmware_version_minor as u8),
            utc_time: t.utc_time.clone(),
        }
    }
}

impl From<&CkInfo> for v1_proto::CryptokiInfo {
    fn from(i: &CkInfo) -> Self {
        v1_proto::CryptokiInfo {
            cryptoki_version_major: i.cryptoki_version.0 as u32,
            cryptoki_version_minor: i.cryptoki_version.1 as u32,
            manufacturer_id: i.manufacturer_id.clone(),
            flags: i.flags,
            library_description: i.library_description.clone(),
            library_version_major: i.library_version.0 as u32,
            library_version_minor: i.library_version.1 as u32,
        }
    }
}

impl From<&v1_proto::CryptokiInfo> for CkInfo {
    fn from(i: &v1_proto::CryptokiInfo) -> Self {
        CkInfo {
            cryptoki_version: (i.cryptoki_version_major as u8, i.cryptoki_version_minor as u8),
            manufacturer_id: i.manufacturer_id.clone(),
            flags: i.flags,
            library_description: i.library_description.clone(),
            library_version: (i.library_version_major as u8, i.library_version_minor as u8),
        }
    }
}

#[cfg(test)]
mod tests;

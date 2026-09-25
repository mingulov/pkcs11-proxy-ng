use crate::pkcs11_proxy_ng::v1 as v1_proto;
use pkcs11_proxy_ng_types::{
    CkFlags, CkInfo, CkResult, CkRv, CkSlotFlags, CkSlotInfo, CkTokenFlags, CkTokenInfo,
};

/// W1-C8-06: PKCS#11 version components are single bytes. A wire value above
/// 255 is corrupt peer data and must error loudly instead of truncating to
/// the low byte. `DEVICE_ERROR` matches the discovery layer's existing signal
/// for unusable peer info payloads.
fn version_byte(value: u32) -> CkResult<u8> {
    u8::try_from(value).map_err(|_| CkRv::DEVICE_ERROR)
}

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

impl TryFrom<&v1_proto::SlotInfo> for CkSlotInfo {
    type Error = CkRv;
    fn try_from(s: &v1_proto::SlotInfo) -> CkResult<Self> {
        Ok(CkSlotInfo {
            slot_description: s.slot_description.clone(),
            manufacturer_id: s.manufacturer_id.clone(),
            flags: CkSlotFlags(s.flags),
            hardware_version: (
                version_byte(s.hardware_version_major)?,
                version_byte(s.hardware_version_minor)?,
            ),
            firmware_version: (
                version_byte(s.firmware_version_major)?,
                version_byte(s.firmware_version_minor)?,
            ),
        })
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

impl TryFrom<&v1_proto::TokenInfo> for CkTokenInfo {
    type Error = CkRv;
    fn try_from(t: &v1_proto::TokenInfo) -> CkResult<Self> {
        Ok(CkTokenInfo {
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
            hardware_version: (
                version_byte(t.hardware_version_major)?,
                version_byte(t.hardware_version_minor)?,
            ),
            firmware_version: (
                version_byte(t.firmware_version_major)?,
                version_byte(t.firmware_version_minor)?,
            ),
            utc_time: t.utc_time.clone(),
        })
    }
}

impl From<&CkInfo> for v1_proto::CryptokiInfo {
    fn from(i: &CkInfo) -> Self {
        v1_proto::CryptokiInfo {
            cryptoki_version_major: i.cryptoki_version.0 as u32,
            cryptoki_version_minor: i.cryptoki_version.1 as u32,
            manufacturer_id: i.manufacturer_id.clone(),
            flags: i.flags.0,
            library_description: i.library_description.clone(),
            library_version_major: i.library_version.0 as u32,
            library_version_minor: i.library_version.1 as u32,
        }
    }
}

impl TryFrom<&v1_proto::CryptokiInfo> for CkInfo {
    type Error = CkRv;
    fn try_from(i: &v1_proto::CryptokiInfo) -> CkResult<Self> {
        Ok(CkInfo {
            cryptoki_version: (
                version_byte(i.cryptoki_version_major)?,
                version_byte(i.cryptoki_version_minor)?,
            ),
            manufacturer_id: i.manufacturer_id.clone(),
            flags: CkFlags(i.flags),
            library_description: i.library_description.clone(),
            library_version: (
                version_byte(i.library_version_major)?,
                version_byte(i.library_version_minor)?,
            ),
        })
    }
}

#[cfg(test)]
mod tests;

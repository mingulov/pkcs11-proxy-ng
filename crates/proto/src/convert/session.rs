use crate::pkcs11_proxy_ng::v1 as v1_proto;
use pkcs11_proxy_ng_types::{CkSessionFlags, CkSessionInfo, CkSessionState, CkSlotId};

impl From<&CkSessionInfo> for v1_proto::SessionInfo {
    fn from(s: &CkSessionInfo) -> Self {
        v1_proto::SessionInfo {
            slot_id: s.slot_id.0,
            state: s.state as u64,
            flags: s.flags.0,
            device_error: s.device_error,
        }
    }
}

impl From<&v1_proto::SessionInfo> for CkSessionInfo {
    fn from(s: &v1_proto::SessionInfo) -> Self {
        let state = match s.state {
            0 => CkSessionState::RoPublic,
            1 => CkSessionState::RoUser,
            2 => CkSessionState::RwPublic,
            3 => CkSessionState::RwUser,
            4 => CkSessionState::RwSo,
            // Unknown session state from wire: default to RoPublic (most restrictive),
            // which is fail-safe — does not grant more access than intended (ADR-0003).
            _ => CkSessionState::RoPublic,
        };
        CkSessionInfo {
            slot_id: CkSlotId(s.slot_id),
            state,
            flags: CkSessionFlags(s.flags),
            device_error: s.device_error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_info_round_trip() {
        let original = CkSessionInfo {
            slot_id: CkSlotId(0),
            state: CkSessionState::RwPublic,
            flags: CkSessionFlags(0x06),
            device_error: 0,
        };
        let proto: v1_proto::SessionInfo = (&original).into();
        let back = CkSessionInfo::from(&proto);
        assert_eq!(back, original);
    }

    #[test]
    fn unknown_session_state_defaults_to_ro_public() {
        let proto = v1_proto::SessionInfo {
            slot_id: 0,
            state: 99, // unknown state value
            flags: 0,
            device_error: 0,
        };
        let back = CkSessionInfo::from(&proto);
        assert_eq!(back.state, CkSessionState::RoPublic);
    }

    #[test]
    fn session_state_rw_user_round_trip() {
        let original = CkSessionInfo {
            slot_id: CkSlotId(1),
            state: CkSessionState::RwUser,
            flags: CkSessionFlags(0x06),
            device_error: 0,
        };
        let proto: v1_proto::SessionInfo = (&original).into();
        let back = CkSessionInfo::from(&proto);
        assert_eq!(back.state, CkSessionState::RwUser);
    }

    #[test]
    fn session_state_ro_public_round_trip() {
        let original = CkSessionInfo {
            slot_id: CkSlotId(0),
            state: CkSessionState::RoPublic,
            flags: CkSessionFlags(0x04), // CKF_SERIAL_SESSION
            device_error: 0,
        };
        let proto: v1_proto::SessionInfo = (&original).into();
        let back = CkSessionInfo::from(&proto);
        assert_eq!(back.state, CkSessionState::RoPublic);
    }

    #[test]
    fn session_state_ro_user_round_trip() {
        let original = CkSessionInfo {
            slot_id: CkSlotId(0),
            state: CkSessionState::RoUser,
            flags: CkSessionFlags(0x04),
            device_error: 0,
        };
        let proto: v1_proto::SessionInfo = (&original).into();
        let back = CkSessionInfo::from(&proto);
        assert_eq!(back.state, CkSessionState::RoUser);
    }

    #[test]
    fn session_state_rw_so_round_trip() {
        let original = CkSessionInfo {
            slot_id: CkSlotId(0),
            state: CkSessionState::RwSo,
            flags: CkSessionFlags(0x06),
            device_error: 0,
        };
        let proto: v1_proto::SessionInfo = (&original).into();
        let back = CkSessionInfo::from(&proto);
        assert_eq!(back.state, CkSessionState::RwSo);
    }

    #[test]
    fn session_device_error_nonzero_preserved() {
        // Non-zero device_error from the backend must survive serialisation.
        let original = CkSessionInfo {
            slot_id: CkSlotId(0),
            state: CkSessionState::RwPublic,
            flags: CkSessionFlags(0x06),
            device_error: 0xDEAD,
        };
        let proto: v1_proto::SessionInfo = (&original).into();
        let back = CkSessionInfo::from(&proto);
        assert_eq!(back.device_error, 0xDEAD);
    }

    #[test]
    fn session_slot_id_large_value_preserved() {
        // The slot ID is a virtual ID assigned by the daemon; large values must
        // pass through without truncation.
        let original = CkSessionInfo {
            slot_id: CkSlotId(u64::MAX),
            state: CkSessionState::RwPublic,
            flags: CkSessionFlags(0x06),
            device_error: 0,
        };
        let proto: v1_proto::SessionInfo = (&original).into();
        let back = CkSessionInfo::from(&proto);
        assert_eq!(back.slot_id, CkSlotId(u64::MAX));
    }

    #[test]
    fn session_all_states_map_correctly() {
        // Enumerate every known wire value to confirm the match arm covers all states.
        let wire_to_state = [
            (0u64, CkSessionState::RoPublic),
            (1, CkSessionState::RoUser),
            (2, CkSessionState::RwPublic),
            (3, CkSessionState::RwUser),
            (4, CkSessionState::RwSo),
        ];
        for (wire, expected) in wire_to_state {
            let proto =
                v1_proto::SessionInfo { slot_id: 0, state: wire, flags: 0, device_error: 0 };
            let back = CkSessionInfo::from(&proto);
            assert_eq!(back.state, expected, "wire value {wire} should map to {expected:?}");
        }
    }
}

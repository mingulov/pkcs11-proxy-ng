use super::*;

#[test]
fn slot_info_round_trip() {
    let original = CkSlotInfo {
        slot_description: "Test Slot".into(),
        manufacturer_id: "Test".into(),
        flags: CkSlotFlags(0x01),
        hardware_version: (1, 2),
        firmware_version: (3, 4),
    };
    let proto: v1_proto::SlotInfo = (&original).into();
    let back = CkSlotInfo::from(&proto);
    assert_eq!(back, original);
}

#[test]
fn token_info_round_trip() {
    let original = CkTokenInfo {
        label: "Test Token".into(),
        manufacturer_id: "Test".into(),
        model: "Model".into(),
        serial_number: "0001".into(),
        flags: CkTokenFlags(0x0404),
        max_session_count: 256,
        session_count: 1,
        max_rw_session_count: 128,
        rw_session_count: 0,
        max_pin_len: 64,
        min_pin_len: 4,
        total_public_memory: u64::MAX,
        free_public_memory: u64::MAX,
        total_private_memory: u64::MAX,
        free_private_memory: u64::MAX,
        hardware_version: (1, 0),
        firmware_version: (2, 3),
        utc_time: "20260312000000".into(),
    };
    let proto: v1_proto::TokenInfo = (&original).into();
    let back = CkTokenInfo::from(&proto);
    assert_eq!(back, original);
}

#[test]
fn cryptoki_info_round_trip() {
    let original = CkInfo {
        cryptoki_version: (3, 0),
        manufacturer_id: "Test".into(),
        flags: 0,
        library_description: "Test Library".into(),
        library_version: (1, 0),
    };
    let proto: v1_proto::CryptokiInfo = (&original).into();
    let back = CkInfo::from(&proto);
    assert_eq!(back, original);
}

#[test]
fn slot_info_max_version_bytes_round_trip() {
    let original = CkSlotInfo {
        slot_description: "Max Version Slot".into(),
        manufacturer_id: "ACME".into(),
        flags: CkSlotFlags(0),
        hardware_version: (255, 255),
        firmware_version: (255, 255),
    };
    let proto: v1_proto::SlotInfo = (&original).into();
    let back = CkSlotInfo::from(&proto);
    assert_eq!(back.hardware_version, (255, 255));
    assert_eq!(back.firmware_version, (255, 255));
}

#[test]
fn slot_info_empty_strings_round_trip() {
    let original = CkSlotInfo {
        slot_description: String::new(),
        manufacturer_id: String::new(),
        flags: CkSlotFlags(0),
        hardware_version: (0, 0),
        firmware_version: (0, 0),
    };
    let proto: v1_proto::SlotInfo = (&original).into();
    let back = CkSlotInfo::from(&proto);
    assert_eq!(back, original);
}

#[test]
fn token_info_ck_unavailable_information_session_counts() {
    let original = CkTokenInfo {
        label: "Token".into(),
        manufacturer_id: "Test".into(),
        model: "M".into(),
        serial_number: "0".into(),
        flags: CkTokenFlags(0),
        max_session_count: u64::MAX,
        session_count: u64::MAX,
        max_rw_session_count: u64::MAX,
        rw_session_count: u64::MAX,
        max_pin_len: 255,
        min_pin_len: 4,
        total_public_memory: u64::MAX,
        free_public_memory: u64::MAX,
        total_private_memory: u64::MAX,
        free_private_memory: u64::MAX,
        hardware_version: (0, 0),
        firmware_version: (0, 0),
        utc_time: String::new(),
    };
    let proto: v1_proto::TokenInfo = (&original).into();
    let back = CkTokenInfo::from(&proto);
    assert_eq!(back.max_session_count, u64::MAX);
    assert_eq!(back.session_count, u64::MAX);
    assert_eq!(back.max_rw_session_count, u64::MAX);
    assert_eq!(back.rw_session_count, u64::MAX);
}

#[test]
fn token_info_all_flags_round_trip() {
    let original = CkTokenInfo {
        label: "Token".into(),
        manufacturer_id: "Test".into(),
        model: "M".into(),
        serial_number: "0".into(),
        flags: CkTokenFlags(u64::MAX),
        max_session_count: 0,
        session_count: 0,
        max_rw_session_count: 0,
        rw_session_count: 0,
        max_pin_len: 0,
        min_pin_len: 0,
        total_public_memory: 0,
        free_public_memory: 0,
        total_private_memory: 0,
        free_private_memory: 0,
        hardware_version: (0, 0),
        firmware_version: (0, 0),
        utc_time: String::new(),
    };
    let proto: v1_proto::TokenInfo = (&original).into();
    let back = CkTokenInfo::from(&proto);
    assert_eq!(back.flags.0, u64::MAX);
}

#[test]
fn token_info_unicode_label_round_trip() {
    let original = CkTokenInfo {
        label: "Токен-测试".into(),
        manufacturer_id: "Test".into(),
        model: "M".into(),
        serial_number: "0".into(),
        flags: CkTokenFlags(0),
        max_session_count: 1,
        session_count: 0,
        max_rw_session_count: 1,
        rw_session_count: 0,
        max_pin_len: 16,
        min_pin_len: 4,
        total_public_memory: 1,
        free_public_memory: 1,
        total_private_memory: 1,
        free_private_memory: 1,
        hardware_version: (1, 0),
        firmware_version: (1, 0),
        utc_time: String::new(),
    };
    let proto: v1_proto::TokenInfo = (&original).into();
    let back = CkTokenInfo::from(&proto);
    assert_eq!(back.label, original.label);
}

#[test]
fn token_info_single_char_fields_round_trip() {
    let original = CkTokenInfo {
        label: "A".into(),
        manufacturer_id: "B".into(),
        model: "C".into(),
        serial_number: "D".into(),
        flags: CkTokenFlags(1),
        max_session_count: 2,
        session_count: 3,
        max_rw_session_count: 4,
        rw_session_count: 5,
        max_pin_len: 6,
        min_pin_len: 7,
        total_public_memory: 8,
        free_public_memory: 9,
        total_private_memory: 10,
        free_private_memory: 11,
        hardware_version: (12, 13),
        firmware_version: (14, 15),
        utc_time: "16".into(),
    };
    let proto: v1_proto::TokenInfo = (&original).into();
    let back = CkTokenInfo::from(&proto);
    assert_eq!(back, original);
}

#[test]
fn token_info_trimmed_strings_round_trip() {
    let original = CkTokenInfo {
        label: " Label ".into(),
        manufacturer_id: " Maker ".into(),
        model: " Model ".into(),
        serial_number: " Serial ".into(),
        flags: CkTokenFlags(0),
        max_session_count: 0,
        session_count: 0,
        max_rw_session_count: 0,
        rw_session_count: 0,
        max_pin_len: 0,
        min_pin_len: 0,
        total_public_memory: 0,
        free_public_memory: 0,
        total_private_memory: 0,
        free_private_memory: 0,
        hardware_version: (0, 0),
        firmware_version: (0, 0),
        utc_time: String::new(),
    };
    let proto: v1_proto::TokenInfo = (&original).into();
    let back = CkTokenInfo::from(&proto);
    assert_eq!(back, original);
}

#[test]
fn cryptoki_info_all_flag_bits_round_trip() {
    let original = CkInfo {
        cryptoki_version: (3, 2),
        manufacturer_id: "Test".into(),
        flags: u64::MAX,
        library_description: "Library".into(),
        library_version: (255, 255),
    };
    let proto: v1_proto::CryptokiInfo = (&original).into();
    let back = CkInfo::from(&proto);
    assert_eq!(back, original);
}

#[test]
fn cryptoki_info_empty_description_round_trip() {
    let original = CkInfo {
        cryptoki_version: (2, 40),
        manufacturer_id: String::new(),
        flags: 0,
        library_description: String::new(),
        library_version: (0, 0),
    };
    let proto: v1_proto::CryptokiInfo = (&original).into();
    let back = CkInfo::from(&proto);
    assert_eq!(back, original);
}

use super::*;

#[test]
fn mock_lifecycle() {
    let backend = MockBackend::default_test();
    assert!(backend.initialize().is_ok());
    assert_eq!(backend.initialize().unwrap_err(), CkRv::CRYPTOKI_ALREADY_INITIALIZED);
    assert!(backend.finalize().is_ok());
}

#[test]
fn mock_session_lifecycle() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let h = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert!(backend.get_session_info(h).is_ok());
    assert!(backend.close_session(h).is_ok());
    assert_eq!(backend.close_session(h).unwrap_err(), CkRv::SESSION_HANDLE_INVALID);
}

#[test]
fn mock_invalid_slot() {
    let backend = MockBackend::default_test();
    assert_eq!(backend.get_slot_info(CkSlotId(99)).unwrap_err(), CkRv::SLOT_ID_INVALID);
    assert_eq!(
        backend.open_session(CkSlotId(99), CkSessionFlags::default()).unwrap_err(),
        CkRv::SLOT_ID_INVALID
    );
}

#[test]
fn mechanism_info_unknown_mechanism_returns_mechanism_invalid() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::SHA256]);
    assert_eq!(
        backend.get_mechanism_info(CkSlotId(0), CkMechanismType::RSA_PKCS).unwrap_err(),
        CkRv::MECHANISM_INVALID
    );
}

#[test]
fn mock_generate_key_pair_returns_unique_handles() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS_KEY_PAIR_GEN, params: None };
    let (pub_h, priv_h) = backend.generate_key_pair(session, &mech, &[], &[]).unwrap();
    assert_ne!(pub_h, priv_h);
}

#[test]
fn mock_generate_random_returns_correct_length() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let random = backend.generate_random(session, 32).unwrap();
    assert_eq!(random.len(), 32);
}

#[test]
fn close_all_sessions_is_slot_scoped() {
    let backend = MockBackend::new(vec![CkSlotId(0), CkSlotId(1)], vec![CkMechanismType::RSA_PKCS]);
    backend.initialize().unwrap();
    let s0 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let s1 = backend.open_session(CkSlotId(1), CkSessionFlags::default()).unwrap();
    backend.close_all_sessions(CkSlotId(0)).unwrap();
    assert_eq!(backend.close_session(s0).unwrap_err(), CkRv::SESSION_HANDLE_INVALID);
    assert!(backend.close_session(s1).is_ok());
}

#[test]
fn mock_encrypt_decrypt_roundtrip() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let key = CkObjectHandle(1);
    backend.encrypt_init(session, &mech, key).unwrap();
    let plaintext = b"hello world";
    let ciphertext = backend.encrypt(session, plaintext).unwrap();
    assert_ne!(ciphertext.as_slice(), plaintext);
    backend.decrypt_init(session, &mech, key).unwrap();
    let recovered = backend.decrypt(session, &ciphertext).unwrap();
    assert_eq!(recovered.as_slice(), plaintext);
}

#[test]
fn get_session_info_returns_correct_slot() {
    let backend = MockBackend::new(vec![CkSlotId(0), CkSlotId(5)], vec![CkMechanismType::RSA_PKCS]);
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(5), CkSessionFlags::default()).unwrap();
    let info = backend.get_session_info(session).unwrap();
    assert_eq!(info.slot_id, CkSlotId(5));
}

const CKF_DONT_BLOCK: u64 = 0x0000_0001;

#[test]
fn wait_for_slot_event_no_event_when_empty() {
    let backend = MockBackend::default_test();
    assert_eq!(backend.wait_for_slot_event(CKF_DONT_BLOCK).unwrap_err(), CkRv::NO_EVENT);
}

#[test]
fn wait_for_slot_event_returns_queued_event() {
    let backend = MockBackend::default_test();
    backend.enqueue_slot_event(CkSlotId(3));
    let slot = backend.wait_for_slot_event(CKF_DONT_BLOCK).unwrap();
    assert_eq!(slot, CkSlotId(3));
}

#[test]
fn wait_for_slot_event_fifo_order() {
    let backend = MockBackend::default_test();
    backend.enqueue_slot_event(CkSlotId(1));
    backend.enqueue_slot_event(CkSlotId(2));
    backend.enqueue_slot_event(CkSlotId(3));
    assert_eq!(backend.wait_for_slot_event(CKF_DONT_BLOCK).unwrap(), CkSlotId(1));
    assert_eq!(backend.wait_for_slot_event(CKF_DONT_BLOCK).unwrap(), CkSlotId(2));
    assert_eq!(backend.wait_for_slot_event(CKF_DONT_BLOCK).unwrap(), CkSlotId(3));
    assert_eq!(backend.wait_for_slot_event(CKF_DONT_BLOCK).unwrap_err(), CkRv::NO_EVENT);
}

#[test]
fn wait_for_slot_event_blocking_flag_same_as_nonblocking_in_mock() {
    let backend = MockBackend::default_test();
    backend.enqueue_slot_event(CkSlotId(7));
    let slot = backend.wait_for_slot_event(0).unwrap();
    assert_eq!(slot, CkSlotId(7));
    assert_eq!(backend.wait_for_slot_event(0).unwrap_err(), CkRv::NO_EVENT);
}

#[test]
fn wait_for_slot_event_event_slots_need_not_be_in_slot_list() {
    let backend = MockBackend::default_test();
    backend.enqueue_slot_event(CkSlotId(99));
    let slot = backend.wait_for_slot_event(CKF_DONT_BLOCK).unwrap();
    assert_eq!(slot, CkSlotId(99));
}

#[test]
fn sign_init_then_sign_single_pass_ok() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    backend.sign_init(session, &mech, CkObjectHandle(1)).unwrap();
    assert!(backend.sign(session, b"data").is_ok());
}

#[test]
fn sign_without_init_returns_operation_not_initialized() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let err = backend.sign(session, b"data").unwrap_err();
    assert_eq!(err, CkRv::OPERATION_NOT_INITIALIZED);
}

#[test]
fn sign_update_without_init_returns_operation_not_initialized() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(
        backend.sign_update(session, b"chunk").unwrap_err(),
        CkRv::OPERATION_NOT_INITIALIZED
    );
}

#[test]
fn sign_final_without_init_returns_operation_not_initialized() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(backend.sign_final(session).unwrap_err(), CkRv::OPERATION_NOT_INITIALIZED);
}

#[test]
fn sign_multi_part_sequence_ok() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    backend.sign_init(session, &mech, CkObjectHandle(1)).unwrap();
    backend.sign_update(session, b"part1").unwrap();
    backend.sign_update(session, b"part2").unwrap();
    assert!(backend.sign_final(session).is_ok());
}

#[test]
fn double_sign_init_returns_operation_active() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    backend.sign_init(session, &mech, CkObjectHandle(1)).unwrap();
    let err = backend.sign_init(session, &mech, CkObjectHandle(1)).unwrap_err();
    assert_eq!(err, CkRv::OPERATION_ACTIVE);
}

#[test]
fn sign_and_digest_interleaving_blocked_by_operation_active() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let sha_mech = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    backend.sign_init(session, &mech, CkObjectHandle(1)).unwrap();
    let err = backend.digest_init(session, &sha_mech).unwrap_err();
    assert_eq!(err, CkRv::OPERATION_ACTIVE);
}

#[test]
fn sign_operations_are_per_session_independent() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let s1 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let s2 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    let sha_mech = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    backend.sign_init(s1, &mech, CkObjectHandle(1)).unwrap();
    backend.digest_init(s2, &sha_mech).unwrap();
    backend.sign_update(s1, b"data").unwrap();
    backend.digest_update(s2, b"data").unwrap();
    backend.sign_final(s1).unwrap();
    backend.digest_final(s2).unwrap();
}

#[test]
fn sign_state_cleared_after_sign_final() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    backend.sign_init(session, &mech, CkObjectHandle(1)).unwrap();
    backend.sign_final(session).unwrap();
    assert!(backend.sign_init(session, &mech, CkObjectHandle(1)).is_ok());
}

#[test]
fn digest_init_then_digest_single_pass_ok() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    backend.digest_init(session, &mech).unwrap();
    assert!(backend.digest(session, b"hello").is_ok());
}

#[test]
fn digest_without_init_returns_operation_not_initialized() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(backend.digest(session, b"data").unwrap_err(), CkRv::OPERATION_NOT_INITIALIZED);
}

#[test]
fn digest_multi_part_sequence_ok() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None };
    backend.digest_init(session, &mech).unwrap();
    backend.digest_update(session, b"chunk1").unwrap();
    backend.digest_update(session, b"chunk2").unwrap();
    assert!(backend.digest_final(session).is_ok());
}

#[test]
fn encrypt_init_then_encrypt_ok() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    backend.encrypt_init(session, &mech, CkObjectHandle(1)).unwrap();
    assert!(backend.encrypt(session, b"plaintext").is_ok());
}

#[test]
fn encrypt_without_init_returns_operation_not_initialized() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(backend.encrypt(session, b"data").unwrap_err(), CkRv::OPERATION_NOT_INITIALIZED);
}

#[test]
fn decrypt_without_init_returns_operation_not_initialized() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(backend.decrypt(session, b"data").unwrap_err(), CkRv::OPERATION_NOT_INITIALIZED);
}

#[test]
fn encrypt_multi_part_sequence_ok() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    backend.encrypt_init(session, &mech, CkObjectHandle(1)).unwrap();
    let _part = backend.encrypt_update(session, b"part1").unwrap();
    assert!(backend.encrypt_final(session).is_ok());
}

#[test]
fn close_session_clears_active_op_state() {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let mech = CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None };
    backend.sign_init(session, &mech, CkObjectHandle(1)).unwrap();
    backend.close_session(session).unwrap();
    let session2 = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    assert_eq!(backend.sign(session2, b"data").unwrap_err(), CkRv::OPERATION_NOT_INITIALIZED);
}

include!("tests_rest.rs");

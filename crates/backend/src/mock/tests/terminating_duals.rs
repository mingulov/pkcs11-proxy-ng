//! Terminating-provider oracle mode for the dual-function + SignRecover
//! NULL-shape regression net (#30/#31, review finding 3).
//!
//! Default mock behavior retains dual/recover operations across
//! malformed calls; real terminating tokens end them. These tests pin
//! the opt-in terminating mode that models a stateful terminating
//! provider: malformed call → `ARGUMENTS_BAD` + termination,
//! follow-up → `OPERATION_NOT_INITIALIZED`, reinit → clean recovery
//! (no wedged `OPERATION_ACTIVE` surprise).

use super::*;

fn terminating_backend() -> (MockBackend, CkSessionHandle, CkObjectHandle) {
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    backend.set_terminating_dual_mode(true);
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let key = live_key(&backend, session);
    (backend, session, key)
}

fn sha256() -> CkMechanism {
    CkMechanism { mechanism_type: CkMechanismType::SHA256, params: None }
}

fn rsa_pkcs() -> CkMechanism {
    CkMechanism { mechanism_type: CkMechanismType::RSA_PKCS, params: None }
}

fn data_spec() -> CkOutputBufferSpec {
    CkOutputBufferSpec { buffer_present: true, buffer_len: 64, length_pointer_null: false }
}

fn null_len_spec() -> CkOutputBufferSpec {
    CkOutputBufferSpec { buffer_present: true, buffer_len: 64, length_pointer_null: true }
}

#[test]
fn terminating_dual_null_part_terminates_and_reinit_recovers() {
    let (backend, session, key) = terminating_backend();
    backend.digest_init(session, &validated(&sha256())).unwrap();
    backend.encrypt_init(session, &validated(&rsa_pkcs()), key).unwrap();

    // Malformed: NULL part, nonzero length → AB.
    let err = backend
        .digest_encrypt_update_exact(session, CkInBuf::Null { len: 16 }, &data_spec())
        .unwrap_err();
    assert_eq!(err, CkRv::ARGUMENTS_BAD);

    // Follow-up well-formed → CNI: the op terminated, not retained.
    let part = [0x41u8; 16];
    let err = backend
        .digest_encrypt_update_exact(session, CkInBuf::Bytes(&part), &data_spec())
        .unwrap_err();
    assert_eq!(err, CkRv::OPERATION_NOT_INITIALIZED);

    // Reinit → OK, OK; update → OK (no wedged OPERATION_ACTIVE).
    backend.digest_init(session, &validated(&sha256())).unwrap();
    backend.encrypt_init(session, &validated(&rsa_pkcs()), key).unwrap();
    let ok =
        backend.digest_encrypt_update_exact(session, CkInBuf::Bytes(&part), &data_spec()).unwrap();
    assert_eq!(ok.ck_rv, CkRv::OK);
}

#[test]
fn terminating_dual_null_outlen_terminates_and_reinit_recovers() {
    let (backend, session, key) = terminating_backend();
    backend.decrypt_init(session, &validated(&rsa_pkcs()), key).unwrap();
    backend.digest_init(session, &validated(&sha256())).unwrap();

    // Malformed: valid part, NULL out-length → AB.
    let part = [0x41u8; 16];
    let ok = backend
        .decrypt_digest_update_exact(session, CkInBuf::Bytes(&part), &null_len_spec())
        .unwrap();
    assert_eq!(ok.ck_rv, CkRv::ARGUMENTS_BAD);

    // Follow-up well-formed → CNI: the op terminated, not retained.
    let err = backend
        .decrypt_digest_update_exact(session, CkInBuf::Bytes(&part), &data_spec())
        .unwrap_err();
    assert_eq!(err, CkRv::OPERATION_NOT_INITIALIZED);

    // Reinit → OK, OK; update → OK.
    backend.decrypt_init(session, &validated(&rsa_pkcs()), key).unwrap();
    backend.digest_init(session, &validated(&sha256())).unwrap();
    let ok =
        backend.decrypt_digest_update_exact(session, CkInBuf::Bytes(&part), &data_spec()).unwrap();
    assert_eq!(ok.ck_rv, CkRv::OK);
}

#[test]
fn terminating_sign_recover_terminates_and_reinit_recovers() {
    let (backend, session, key) = terminating_backend();
    backend.sign_recover_init(session, &validated(&rsa_pkcs()), key).unwrap();

    // Malformed: NULL data, nonzero length → AB.
    let spec =
        CkOutputBufferSpec { buffer_present: true, buffer_len: 512, length_pointer_null: false };
    let err = backend.sign_recover_exact(session, CkInBuf::Null { len: 32 }, &spec).unwrap_err();
    assert_eq!(err, CkRv::ARGUMENTS_BAD);

    // Follow-up well-formed → CNI: the op terminated, not retained.
    let data = [0x42u8; 32];
    let err = backend.sign_recover_exact(session, CkInBuf::Bytes(&data), &spec).unwrap_err();
    assert_eq!(err, CkRv::OPERATION_NOT_INITIALIZED);

    // Reinit → OK; well-formed recover → OK single-pass success.
    backend.sign_recover_init(session, &validated(&rsa_pkcs()), key).unwrap();
    let ok = backend.sign_recover_exact(session, CkInBuf::Bytes(&data), &spec).unwrap();
    assert_eq!(ok.ck_rv, CkRv::OK);
    assert!(ok.value.is_some(), "well-formed recover must produce a signature");
}

#[test]
fn terminating_mode_records_function_and_shapes() {
    let (backend, session, key) = terminating_backend();
    backend.digest_init(session, &validated(&sha256())).unwrap();
    backend.encrypt_init(session, &validated(&rsa_pkcs()), key).unwrap();

    backend
        .digest_encrypt_update_exact(session, CkInBuf::Null { len: 16 }, &data_spec())
        .unwrap_err();
    let obs = backend.last_data_op_observation().expect("observation recorded");
    assert_eq!(obs.function, "digest_encrypt_update");
    assert!(obs.input_null, "NULL input class must survive to the backend");
    assert_eq!(obs.input_len, 16, "claimed input length must survive");
    assert!(obs.out_buffer_present);
    assert_eq!(obs.out_buffer_len, 64);
    assert!(!obs.length_pointer_null);

    // Second leg overwrites with its own shape (NULL out-length).
    let part = [0x41u8; 16];
    backend.digest_init(session, &validated(&sha256())).unwrap();
    backend.encrypt_init(session, &validated(&rsa_pkcs()), key).unwrap();
    backend.digest_encrypt_update_exact(session, CkInBuf::Bytes(&part), &null_len_spec()).unwrap();
    let obs = backend.last_data_op_observation().expect("observation recorded");
    assert_eq!(obs.function, "digest_encrypt_update");
    assert!(!obs.input_null);
    assert_eq!(obs.input_len, 16);
    assert!(obs.length_pointer_null, "NULL length pointer must survive");
}

#[test]
fn terminating_duplicate_init_is_operation_active() {
    // Real-token control: init while the leg is already active → 0x90.
    // This is what makes reinit-after-malformed discriminate BOTH legs
    // (a surviving leg answers 0x90 instead of OK).
    let (backend, session, key) = terminating_backend();
    backend.digest_init(session, &validated(&sha256())).unwrap();
    assert_eq!(
        backend.digest_init(session, &validated(&sha256())).unwrap_err(),
        CkRv::OPERATION_ACTIVE
    );
    backend.encrypt_init(session, &validated(&rsa_pkcs()), key).unwrap();
    assert_eq!(
        backend.encrypt_init(session, &validated(&rsa_pkcs()), key).unwrap_err(),
        CkRv::OPERATION_ACTIVE
    );
    // The other leg is independent: a live digest does not block encrypt.
    backend.digest_init_cancel(session).unwrap();
    backend.digest_init(session, &validated(&sha256())).unwrap();
}

#[test]
fn terminating_recover_size_query_retains_operation() {
    // Real-token behavior: a size query (no buffer) does not end the
    // single-pass op; the sized call afterwards succeeds.
    let (backend, session, key) = terminating_backend();
    backend.sign_recover_init(session, &validated(&rsa_pkcs()), key).unwrap();
    let data = [0x42u8; 32];
    let size_spec =
        CkOutputBufferSpec { buffer_present: false, buffer_len: 0, length_pointer_null: false };
    let size = backend.sign_recover_exact(session, CkInBuf::Bytes(&data), &size_spec).unwrap();
    assert_eq!(size.ck_rv, CkRv::OK);
    assert!(size.value.is_none(), "size query carries no value");
    let spec =
        CkOutputBufferSpec { buffer_present: true, buffer_len: 512, length_pointer_null: false };
    let ok = backend.sign_recover_exact(session, CkInBuf::Bytes(&data), &spec).unwrap();
    assert_eq!(ok.ck_rv, CkRv::OK, "op must survive the size query");
    assert!(ok.value.is_some());
}

#[test]
fn terminating_recover_buffer_too_small_retains_operation() {
    // Real-token behavior: BUFFER_TOO_SMALL does not end the op; the
    // retry with a sufficient buffer succeeds.
    let (backend, session, key) = terminating_backend();
    backend.sign_recover_init(session, &validated(&rsa_pkcs()), key).unwrap();
    let data = [0x42u8; 32];
    let tiny_spec =
        CkOutputBufferSpec { buffer_present: true, buffer_len: 1, length_pointer_null: false };
    let short = backend.sign_recover_exact(session, CkInBuf::Bytes(&data), &tiny_spec).unwrap();
    assert_eq!(short.ck_rv, CkRv::BUFFER_TOO_SMALL);
    let spec =
        CkOutputBufferSpec { buffer_present: true, buffer_len: 512, length_pointer_null: false };
    let ok = backend.sign_recover_exact(session, CkInBuf::Bytes(&data), &spec).unwrap();
    assert_eq!(ok.ck_rv, CkRv::OK, "op must survive BUFFER_TOO_SMALL");
    assert!(ok.value.is_some());
}

#[test]
fn terminating_mode_off_preserves_legacy_dual_behavior() {
    // Default mode is untouched: duals need no init, and a NULL part
    // still answers AB from input resolution (no op gate, no CNI).
    let backend = MockBackend::default_test();
    backend.initialize().unwrap();
    let session = backend.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
    let err = backend
        .digest_encrypt_update_exact(session, CkInBuf::Null { len: 16 }, &data_spec())
        .unwrap_err();
    assert_eq!(err, CkRv::ARGUMENTS_BAD);
}

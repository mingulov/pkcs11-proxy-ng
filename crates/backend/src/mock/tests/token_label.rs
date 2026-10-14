//! Q03 phase 2: `MockBackend::init_token` exact-label behavior — NULL
//! refusal without side effects, verbatim invalid-byte storage, and
//! the valid-label string/exact interop invariant.

use super::*;

fn q03_pad_label(prefix: &[u8]) -> [u8; PKCS11_TOKEN_LABEL_LEN] {
    let mut label = [b' '; PKCS11_TOKEN_LABEL_LEN];
    label[..prefix.len()].copy_from_slice(prefix);
    label
}

#[test]
fn q03_mock_null_label_refuses_without_touching_identity() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::SHA256]);
    backend.initialize().unwrap();
    backend
        .init_token(CkSlotId(0), Some(b"1234"), InitTokenLabel::text_only("Baseline"))
        .expect("baseline reinit succeeds");
    assert_eq!(
        backend.token_label_bytes(CkSlotId(0)),
        Some(q03_pad_label(b"Baseline")),
        "baseline bytes are recorded"
    );
    assert_eq!(
        backend.init_token_requested_slots(),
        vec![CkSlotId(0)],
        "baseline reached the backend once"
    );

    assert_eq!(
        backend
            .init_token(
                CkSlotId(0),
                Some(b"1234"),
                InitTokenLabel { text: "", exact: Some(ExactTokenLabel::Null) },
            )
            .unwrap_err(),
        CkRv::ARGUMENTS_BAD,
        "mock refuses NULL like observed SoftHSM2"
    );
    // The refusal reached the backend (provider decided) but stored
    // nothing: label bytes and the String identity are unchanged.
    assert_eq!(
        backend.init_token_requested_slots(),
        vec![CkSlotId(0), CkSlotId(0)],
        "the refusal still reached the backend"
    );
    assert_eq!(
        backend.token_label_bytes(CkSlotId(0)),
        Some(q03_pad_label(b"Baseline")),
        "NULL refusal leaves the stored label bytes unchanged"
    );
    assert_eq!(
        backend.get_token_info(CkSlotId(0)).expect("token info").label,
        "Baseline",
        "NULL refusal leaves the token identity unchanged"
    );
}

#[test]
fn q03_mock_exact_bytes_store_verbatim() {
    let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::SHA256]);
    backend.initialize().unwrap();
    let raw = q03_pad_label(b"BAD\xff\xfe");
    backend
        .init_token(
            CkSlotId(0),
            Some(b"1234"),
            InitTokenLabel { text: "BAD\u{fffd}", exact: Some(ExactTokenLabel::Bytes(raw)) },
        )
        .expect("mock accepts invalid-encoding bytes like observed SoftHSM2");
    assert_eq!(
        backend.token_label_bytes(CkSlotId(0)),
        Some(raw),
        "invalid-encoding bytes are stored verbatim, never U+FFFD-substituted"
    );
}

#[test]
fn q03_mock_valid_label_string_and_exact_paths_agree() {
    // Interop invariant at the mock boundary: for every valid vector,
    // the legacy string path and the exact path store identical bytes.
    for (text, raw) in [
        ("hello", q03_pad_label(b"hello")),
        ("tökén-héllo", q03_pad_label("tökén-héllo".as_bytes())),
        ("0123456789abcdef0123456789abcdef", *b"0123456789abcdef0123456789abcdef"),
        ("A\t", q03_pad_label(b"A\t")),
        ("B\u{a0}", q03_pad_label("B\u{a0}".as_bytes())),
        ("", [b' '; PKCS11_TOKEN_LABEL_LEN]),
        ("C\0D", q03_pad_label(b"C\0D")),
    ] {
        let backend = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::SHA256]);
        backend.initialize().unwrap();
        backend
            .init_token(CkSlotId(0), Some(b"1234"), InitTokenLabel::text_only(text))
            .expect("string path accepts the valid label");
        let via_string = backend.token_label_bytes(CkSlotId(0));
        backend
            .init_token(
                CkSlotId(0),
                Some(b"1234"),
                InitTokenLabel { text, exact: Some(ExactTokenLabel::Bytes(raw)) },
            )
            .expect("exact path accepts the valid label");
        let via_exact = backend.token_label_bytes(CkSlotId(0));
        assert_eq!(via_string, Some(raw), "string path stores {text:?} byte-exact");
        assert_eq!(
            via_exact, via_string,
            "exact path stores {text:?} byte-identically to the string path"
        );
    }
}

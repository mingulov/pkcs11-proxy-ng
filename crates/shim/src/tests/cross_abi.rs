//! In-process cross-ABI topology suite (ADR-0011).
//!
//! Each test drives the full shim -> gRPC -> in-process daemon stack
//! against a MockBackend that EMULATES a foreign backend ABI, so both
//! width-bridge directions and the CK_ATTRIBUTE stride translation run
//! in plain `cargo test` on any host — no i686 toolchain, SoftHSM2, or
//! wine required. On an LP64 host the Ilp32/Llp64 daemons exercise the
//! wide-client/narrow-backend direction; on an i686 host the same tests
//! exercise narrow-client/narrow-backend plus the Llp64 stride delta.
//!
//! The live scripts (`scripts/run-cross-width-live-test.sh`,
//! `scripts/run-*-wine-smoke.sh`) remain the real-binary proof; this
//! module is the fast, deterministic everyday coverage.

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_backend::mock::{MockAbi, MockAttributeSlot};
use pkcs11_proxy_ng_types::{CkAttributeType, CkAttributeValue, CkObjectHandle};

use super::output_semantics::{
    CKA_WRAP_TEMPLATE_RAW, ShimSession, TestDaemon, backend_object_handle, create_object,
};
use super::*;

/// One session against a daemon whose backend emulates `abi`.
fn session_on(abi: MockAbi) -> (&'static TestDaemon, ShimSession) {
    let daemon = TestDaemon::shared_with_abi(abi);
    let session = ShimSession::with_endpoint(&daemon.endpoint);
    (daemon, session)
}

fn foreign_profiles() -> [MockAbi; 2] {
    [MockAbi::Ilp32, MockAbi::Llp64]
}

// Input-template width bridging remains supported. Inspect its stored typed
// value through the daemon API when the C ABI cannot safely pre-type an output
// nested materialization across widths.
fn assert_backend_nested_class(abi: MockAbi, object: CK_OBJECT_HANDLE, expected: CK_ULONG) {
    use pkcs11_proxy_ng_types::{CkAttributeQuery, CkSessionFlags, CkSlotId};
    let daemon = TestDaemon::shared_with_abi(abi);
    let object = backend_object_handle(daemon, object);
    let session = daemon
        .backend
        .open_session(CkSlotId(0), CkSessionFlags(CkSessionFlags::SERIAL_SESSION))
        .unwrap();
    let (rv, results) = daemon
        .backend
        .get_attribute_value_exact(
            session,
            object,
            &[CkAttributeQuery {
                attr_type: CkAttributeType::WRAP_TEMPLATE,
                buffer_present: true,
                buffer_len: abi.attribute_stride() as u64,
                nested: Some(vec![CkAttributeQuery {
                    attr_type: CkAttributeType(0),
                    buffer_present: true,
                    buffer_len: abi.ulong_width() as u64,
                    nested: None,
                }]),
            }],
        )
        .unwrap();
    daemon.backend.close_session(session).unwrap();
    assert_eq!(rv, pkcs11_proxy_ng_types::CkRv::OK);
    let result = &results[0].nested.as_ref().unwrap()[0];
    assert_eq!(result.attr_type, CkAttributeType::CLASS);
    assert!(result.value.as_ref().unwrap().expose(|raw| raw == abi.encode_ulong(expected as u64)));
}

#[test]
fn probe_records_each_emulated_profile() {
    let _guard = shim_state_test_guard();
    for abi in foreign_profiles() {
        let (_daemon, shim) = session_on(abi);
        assert_eq!(
            crate::interface_probe::backend_ulong_size(),
            abi.ulong_width(),
            "D2 width for {abi:?}"
        );
        assert_eq!(
            crate::interface_probe::backend_attribute_stride(),
            abi.attribute_stride(),
            "D2 stride for {abi:?}"
        );
        drop(shim);
    }
}

#[test]
fn scalar_ulong_attribute_bridges_both_directions() {
    let _guard = shim_state_test_guard();
    for abi in foreign_profiles() {
        let (daemon, shim) = session_on(abi);
        let object = create_object(shim.session);
        let backend_object = backend_object_handle(daemon, object);
        daemon.backend.set_attribute(
            backend_object,
            CkAttributeType::CLASS,
            MockAttributeSlot::Value(CkAttributeValue::Ulong(3)),
        );

        // Size query: the CLIENT's width, whatever the backend emulates.
        let mut attr =
            CK_ATTRIBUTE { type_: CKA_CLASS, pValue: std::ptr::null_mut(), ulValueLen: 0 };
        let rv =
            unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };
        assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} size query");
        assert_eq!(
            attr.ulValueLen as usize,
            std::mem::size_of::<CK_ULONG>(),
            "{abi:?}: size query must report the client width"
        );

        // Exact-fit data query: value re-encoded to the client width.
        let mut buf = [0u8; std::mem::size_of::<CK_ULONG>()];
        let mut attr = CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: buf.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: buf.len() as CK_ULONG,
        };
        let rv =
            unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };
        assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} data query");
        assert_eq!(CK_ULONG::from_le_bytes(buf), 3, "{abi:?}: value round-trip");

        // Too-small buffer: verbatim CKR_BUFFER_TOO_SMALL and the D10
        // sentinel arrives at the CLIENT's width.
        let mut tiny = [0u8; 2];
        let mut attr = CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: tiny.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: tiny.len() as CK_ULONG,
        };
        let rv =
            unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };
        assert_eq!(rv, CKR_BUFFER_TOO_SMALL as CK_RV, "{abi:?} too-small");
        // E0793: CK_ATTRIBUTE is packed on Windows; assert on a by-value copy.
        let ul_value_len = attr.ulValueLen;
        assert_eq!(ul_value_len, CK_UNAVAILABLE_INFORMATION, "{abi:?}: client-width sentinel");
    }
}

#[test]
fn ulong_array_attribute_bridges_element_wise() {
    let _guard = shim_state_test_guard();
    let mechs: [u64; 3] = [0x1081, 0x1082, 0x0209];
    for abi in foreign_profiles() {
        let (daemon, shim) = session_on(abi);
        let object = create_object(shim.session);
        let backend_object = backend_object_handle(daemon, object);
        // The mock stores the BACKEND-native encoding of the array.
        let backend_bytes: Vec<u8> = mechs.iter().flat_map(|m| abi.encode_ulong(*m)).collect();
        daemon.backend.set_attribute(
            backend_object,
            CkAttributeType::ALLOWED_MECHANISMS,
            MockAttributeSlot::Value(CkAttributeValue::Bytes(backend_bytes.into())),
        );

        let mut attr = CK_ATTRIBUTE {
            type_: CKA_ALLOWED_MECHANISMS,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        };
        let rv =
            unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };
        assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} array size query");
        assert_eq!(
            attr.ulValueLen as usize,
            mechs.len() * std::mem::size_of::<CK_ULONG>(),
            "{abi:?}: array length rescaled by element count"
        );

        let mut buf = vec![0u8; mechs.len() * std::mem::size_of::<CK_ULONG>()];
        let mut attr = CK_ATTRIBUTE {
            type_: CKA_ALLOWED_MECHANISMS,
            pValue: buf.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: buf.len() as CK_ULONG,
        };
        let rv =
            unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };
        assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} array data query");
        for (i, expected) in mechs.iter().enumerate() {
            let w = std::mem::size_of::<CK_ULONG>();
            let got = CK_ULONG::from_le_bytes(buf[i * w..(i + 1) * w].try_into().expect("element"));
            assert_eq!(got as u64, *expected, "{abi:?}: array element {i}");
        }
    }
}

fn set_nested_wrap_template(daemon: &TestDaemon, backend_object: CkObjectHandle) {
    daemon.backend.set_attribute(
        backend_object,
        CkAttributeType::WRAP_TEMPLATE,
        MockAttributeSlot::NestedTemplate(vec![
            (CkAttributeType::CLASS, MockAttributeSlot::Value(CkAttributeValue::Ulong(3))),
            (CkAttributeType::KEY_TYPE, MockAttributeSlot::Value(CkAttributeValue::Ulong(31))),
        ]),
    );
}

#[test]
fn nested_template_pure_size_query_reports_client_layout() {
    let _guard = shim_state_test_guard();
    for abi in foreign_profiles() {
        let (daemon, shim) = session_on(abi);
        let object = create_object(shim.session);
        set_nested_wrap_template(daemon, backend_object_handle(daemon, object));

        // Pure size query: the wire carries the BACKEND-layout template
        // byte length (2 x emulated stride); the caller must see the
        // CLIENT layout (2 x local sizeof(CK_ATTRIBUTE)).
        let mut attr = CK_ATTRIBUTE {
            type_: CKA_WRAP_TEMPLATE_RAW,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        };
        let rv =
            unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };
        assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} nested size query");
        assert_eq!(
            attr.ulValueLen as usize,
            2 * std::mem::size_of::<CK_ATTRIBUTE>(),
            "{abi:?}: nested size query must be rescaled to the client stride"
        );
    }
}

#[test]
fn nested_template_data_query_bridges_sub_values() {
    let _guard = shim_state_test_guard();
    for abi in foreign_profiles() {
        let (daemon, shim) = session_on(abi);
        let object = create_object(shim.session);
        set_nested_wrap_template(daemon, backend_object_handle(daemon, object));

        let w = std::mem::size_of::<CK_ULONG>();
        let mut class_buf = vec![0u8; w];
        let mut key_type_buf = vec![0u8; w];
        let mut sub_attrs = [
            CK_ATTRIBUTE {
                type_: 0,
                pValue: class_buf.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: w as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: 0,
                pValue: key_type_buf.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: w as CK_ULONG,
            },
        ];
        let mut attr = CK_ATTRIBUTE {
            type_: CKA_WRAP_TEMPLATE_RAW,
            pValue: sub_attrs.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: (sub_attrs.len() * std::mem::size_of::<CK_ATTRIBUTE>()) as CK_ULONG,
        };
        let rv =
            unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };
        if abi.ulong_width() != w {
            assert_eq!(
                rv, CKR_FUNCTION_NOT_SUPPORTED,
                "{abi:?} unknown nested output type cannot be width-bridged"
            );
            assert_eq!(class_buf, vec![0; w]);
            assert_eq!(key_type_buf, vec![0; w]);
            let ul_value_len = sub_attrs[0].ulValueLen;
            assert_eq!(ul_value_len, w as CK_ULONG);
            continue;
        }
        assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} nested data query");
        let class_bytes: [u8; std::mem::size_of::<CK_ULONG>()] =
            class_buf.as_slice().try_into().expect("class width");
        let key_bytes: [u8; std::mem::size_of::<CK_ULONG>()] =
            key_type_buf.as_slice().try_into().expect("key width");
        assert_eq!(CK_ULONG::from_le_bytes(class_bytes), 3, "{abi:?}: CLASS sub-value");
        assert_eq!(CK_ULONG::from_le_bytes(key_bytes), 31, "{abi:?}: KEY_TYPE sub-value");
        assert_eq!(sub_attrs[0].ulValueLen as usize, w, "{abi:?}: sub length at client width");
    }
}

#[test]
fn nested_template_sub_too_small_yields_client_width_sentinel() {
    let _guard = shim_state_test_guard();
    for abi in foreign_profiles() {
        let (daemon, shim) = session_on(abi);
        let object = create_object(shim.session);
        set_nested_wrap_template(daemon, backend_object_handle(daemon, object));

        let w = std::mem::size_of::<CK_ULONG>();
        // First sub-buffer deliberately half a client ulong; second exact.
        let mut small = vec![0u8; w / 2];
        let mut ok_buf = vec![0u8; w];
        let mut sub_attrs = [
            CK_ATTRIBUTE {
                type_: 0,
                pValue: small.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: small.len() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: 0,
                pValue: ok_buf.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: ok_buf.len() as CK_ULONG,
            },
        ];
        let mut attr = CK_ATTRIBUTE {
            type_: CKA_WRAP_TEMPLATE_RAW,
            pValue: sub_attrs.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: (sub_attrs.len() * std::mem::size_of::<CK_ATTRIBUTE>()) as CK_ULONG,
        };
        let rv =
            unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };
        if abi.ulong_width() != w {
            assert_eq!(rv, CKR_FUNCTION_NOT_SUPPORTED);
            let ul_value_len = sub_attrs[0].ulValueLen;
            assert_eq!(ul_value_len, (w / 2) as CK_ULONG);
            assert_eq!(small, vec![0; w / 2]);
            assert_eq!(ok_buf, vec![0; w]);
            continue;
        }
        assert_eq!(rv, CKR_BUFFER_TOO_SMALL as CK_RV, "{abi:?} sub-too-small overall rv");
        let ul_value_len = sub_attrs[0].ulValueLen;
        assert_eq!(
            ul_value_len, CK_UNAVAILABLE_INFORMATION,
            "{abi:?}: too-small sub gets the client-width sentinel"
        );
        let ok_bytes: [u8; std::mem::size_of::<CK_ULONG>()] =
            ok_buf.as_slice().try_into().expect("width");
        assert_eq!(
            CK_ULONG::from_le_bytes(ok_bytes),
            31,
            "{abi:?}: the adequately-sized sub still round-trips"
        );
    }
}

#[test]
fn big_endian_backend_is_refused_at_initialize() {
    // D6: the wire carries backend-native ulong bytes, so a byte-order
    // mismatch would corrupt every multi-byte value. The shim must refuse
    // at C_Initialize — loudly, before any value can be parsed — with the
    // lifecycle-class error, never connect-and-corrupt.
    let _guard = shim_state_test_guard();
    let daemon = TestDaemon::shared_big_endian();
    unsafe {
        std::env::set_var("PKCS11_PROXY_ENDPOINT", &daemon.endpoint);
    }
    let rv = unsafe { dispatch::general::c_initialize(std::ptr::null_mut()) };
    if rv == CKR_OK as CK_RV {
        // Clean up so a failing assertion doesn't poison other tests.
        let _ = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
    }
    assert_eq!(rv, CKR_GENERAL_ERROR as CK_RV, "a D6 byte-order mismatch must fail C_Initialize");
}

#[test]
fn create_with_template_round_trips_across_abis() {
    // Typed ulong template input is width-independent (D1), and vendor
    // attributes pass through as opaque bytes (D7) at ANY width: the
    // whole create -> store -> read-back loop must hold on foreign ABIs.
    let _guard = shim_state_test_guard();
    const VENDOR_ATTR: CK_ATTRIBUTE_TYPE = 0x8000_0042;
    for abi in foreign_profiles() {
        let (_daemon, shim) = session_on(abi);

        let mut class: CK_ULONG = CKO_DATA;
        let mut vendor_bytes = [9u8, 8, 7];
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: &mut class as *mut CK_ULONG as CK_VOID_PTR,
                ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: VENDOR_ATTR,
                pValue: vendor_bytes.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: vendor_bytes.len() as CK_ULONG,
            },
        ];
        let mut object = CK_INVALID_HANDLE;
        let rv = unsafe {
            dispatch::general::c_create_object(
                shim.session,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut object,
            )
        };
        assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} C_CreateObject with template");

        // CKA_CLASS reads back at the CLIENT width regardless of the
        // backend's storage width.
        let mut class_buf = [0u8; std::mem::size_of::<CK_ULONG>()];
        let mut attr = CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: class_buf.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: class_buf.len() as CK_ULONG,
        };
        let rv =
            unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };
        assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} CLASS read-back");
        assert_eq!(CK_ULONG::from_le_bytes(class_buf), CKO_DATA, "{abi:?} CLASS value");

        // The vendor attribute's bytes are untouched by any width bridge.
        let mut vendor_buf = [0u8; 3];
        let mut attr = CK_ATTRIBUTE {
            type_: VENDOR_ATTR,
            pValue: vendor_buf.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: vendor_buf.len() as CK_ULONG,
        };
        let rv =
            unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };
        assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} vendor read-back");
        assert_eq!(vendor_buf, [9, 8, 7], "{abi:?}: vendor bytes are opaque (D7)");
        let ul_value_len = attr.ulValueLen;
        assert_eq!(ul_value_len, 3, "{abi:?}: vendor length is byte-addressed");
    }
}

#[test]
fn nested_template_input_round_trips_across_abis() {
    // Input direction (the historically missing half): CKA_WRAP_TEMPLATE
    // inside a C_CreateObject template crosses the wire STRUCTURALLY —
    // never as raw client CK_ATTRIBUTE struct bytes, whose pointers would
    // be dangling in the daemon. The backend stores it and the nested
    // OUTPUT path serves it back at the client's own layout.
    let _guard = shim_state_test_guard();
    for abi in foreign_profiles() {
        let (_daemon, shim) = session_on(abi);

        let mut sub_class: CK_ULONG = 4; // CKO_SECRET_KEY
        let mut wrap_subs = [CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: &mut sub_class as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        }];
        let mut template = [CK_ATTRIBUTE {
            type_: CKA_WRAP_TEMPLATE_RAW,
            pValue: wrap_subs.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: std::mem::size_of_val(&wrap_subs) as CK_ULONG,
        }];
        let mut object = CK_INVALID_HANDLE;
        let rv = unsafe {
            dispatch::general::c_create_object(
                shim.session,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut object,
            )
        };
        assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} create with nested template input");

        // Read back: pure size query first (client layout), then the data.
        let mut attr = CK_ATTRIBUTE {
            type_: CKA_WRAP_TEMPLATE_RAW,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        };
        let rv =
            unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };
        assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} nested size query");
        assert_eq!(
            attr.ulValueLen as usize,
            std::mem::size_of::<CK_ATTRIBUTE>(),
            "{abi:?}: one sub-attribute at the client stride"
        );

        let w = std::mem::size_of::<CK_ULONG>();
        let mut class_buf = vec![0u8; w];
        let mut out_subs = [CK_ATTRIBUTE {
            type_: 0,
            pValue: class_buf.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: w as CK_ULONG,
        }];
        let mut attr = CK_ATTRIBUTE {
            type_: CKA_WRAP_TEMPLATE_RAW,
            pValue: out_subs.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: std::mem::size_of_val(&out_subs) as CK_ULONG,
        };
        let rv =
            unsafe { dispatch::general::c_get_attribute_value(shim.session, object, &mut attr, 1) };
        if abi.ulong_width() != w {
            assert_eq!(rv, CKR_FUNCTION_NOT_SUPPORTED);
            assert_eq!(class_buf, vec![0; w]);
            assert_backend_nested_class(abi, object, 4);
            continue;
        }
        assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} nested data query");
        let sub_type = out_subs[0].type_;
        assert_eq!(sub_type, CKA_CLASS, "{abi:?}: sub type");
        let class_bytes: [u8; std::mem::size_of::<CK_ULONG>()] =
            class_buf.as_slice().try_into().expect("width");
        assert_eq!(
            CK_ULONG::from_le_bytes(class_bytes),
            4,
            "{abi:?}: sub-value round-trips through input AND output bridging"
        );
    }
}

/// Read back CKA_WRAP_TEMPLATE from `object` and assert it holds exactly
/// one CKA_CLASS sub-attribute with `expected_class`, at the client's
/// own layout and width.
fn assert_wrap_template_holds_class(
    abi: MockAbi,
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    expected_class: CK_ULONG,
    context: &str,
) {
    let w = std::mem::size_of::<CK_ULONG>();
    let mut class_buf = vec![0u8; w];
    let mut out_subs = [CK_ATTRIBUTE {
        type_: 0,
        pValue: class_buf.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: w as CK_ULONG,
    }];
    let mut attr = CK_ATTRIBUTE {
        type_: CKA_WRAP_TEMPLATE_RAW,
        pValue: out_subs.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: std::mem::size_of_val(&out_subs) as CK_ULONG,
    };
    let rv = unsafe { dispatch::general::c_get_attribute_value(session, object, &mut attr, 1) };
    if abi.ulong_width() != w {
        assert_eq!(rv, CKR_FUNCTION_NOT_SUPPORTED);
        assert_eq!(class_buf, vec![0; w]);
        assert_backend_nested_class(abi, object, expected_class);
        return;
    }
    assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} {context}: nested read-back");
    let sub_type = out_subs[0].type_;
    assert_eq!(sub_type, CKA_CLASS, "{abi:?} {context}: sub type");
    let bytes: [u8; std::mem::size_of::<CK_ULONG>()] =
        class_buf.as_slice().try_into().expect("width");
    assert_eq!(
        CK_ULONG::from_le_bytes(bytes),
        expected_class,
        "{abi:?} {context}: sub-value at client width"
    );
}

#[test]
fn nested_template_input_round_trips_via_every_template_call() {
    // The four remaining template-carrying entry points: C_GenerateKey,
    // C_UnwrapKey, C_CopyObject, and C_SetAttributeValue must all carry a
    // nested CKA_WRAP_TEMPLATE structurally, cross-ABI, like C_CreateObject.
    let _guard = shim_state_test_guard();
    for abi in foreign_profiles() {
        let (_daemon, shim) = session_on(abi);

        let mut sub_class: CK_ULONG = 4;
        let mut wrap_subs = [CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: &mut sub_class as *mut CK_ULONG as CK_VOID_PTR,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        }];
        let mut template = [CK_ATTRIBUTE {
            type_: CKA_WRAP_TEMPLATE_RAW,
            pValue: wrap_subs.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: std::mem::size_of_val(&wrap_subs) as CK_ULONG,
        }];
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        // C_GenerateKey
        let mut generated = CK_INVALID_HANDLE;
        let rv = unsafe {
            dispatch::general::c_generate_key(
                shim.session,
                &mut mechanism,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut generated,
            )
        };
        assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} C_GenerateKey");
        assert_wrap_template_holds_class(abi, shim.session, generated, 4, "generate_key");

        // C_UnwrapKey
        let mut wrapped = [0u8; 8];
        let mut unwrapped = CK_INVALID_HANDLE;
        let rv = unsafe {
            dispatch::general::c_unwrap_key(
                shim.session,
                &mut mechanism,
                generated,
                wrapped.as_mut_ptr(),
                wrapped.len() as CK_ULONG,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut unwrapped,
            )
        };
        assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} C_UnwrapKey");
        assert_wrap_template_holds_class(abi, shim.session, unwrapped, 4, "unwrap_key");

        // C_CopyObject (template applies to the copy)
        let plain = create_object(shim.session);
        let mut copy = CK_INVALID_HANDLE;
        let rv = unsafe {
            dispatch::general::c_copy_object(
                shim.session,
                plain,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut copy,
            )
        };
        assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} C_CopyObject");
        assert_wrap_template_holds_class(abi, shim.session, copy, 4, "copy_object");

        // C_SetAttributeValue (merges into an existing object)
        let target = create_object(shim.session);
        let rv = unsafe {
            dispatch::general::c_set_attribute_value(
                shim.session,
                target,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
            )
        };
        assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} C_SetAttributeValue");
        assert_wrap_template_holds_class(abi, shim.session, target, 4, "set_attribute_value");
    }
}

#[test]
fn sign_then_verify_round_trips_through_the_proxy_cross_abi() {
    // A2 lossless-loop: the mock now VERIFIES (signature must reproduce
    // the sign echo of the data). A sign->verify round-trip through the
    // full shim->gRPC->daemon stack therefore proves no byte was lost or
    // corrupted in either direction — on foreign-ABI daemons too.
    let _guard = shim_state_test_guard();
    for abi in foreign_profiles() {
        let (_daemon, shim) = session_on(abi);
        let key = create_object(shim.session);
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let data = b"cross-abi integrity";

        assert_eq!(
            unsafe { dispatch::general::c_sign_init(shim.session, &mut mechanism, key) },
            CKR_OK as CK_RV,
            "{abi:?} C_SignInit"
        );
        let mut sig_len: CK_ULONG = 0;
        assert_eq!(
            unsafe {
                dispatch::general::c_sign(
                    shim.session,
                    data.as_ptr() as CK_BYTE_PTR,
                    data.len() as CK_ULONG,
                    std::ptr::null_mut(),
                    &mut sig_len,
                )
            },
            CKR_OK as CK_RV,
            "{abi:?} C_Sign size query"
        );
        let mut signature = vec![0u8; sig_len as usize];
        assert_eq!(
            unsafe {
                dispatch::general::c_sign(
                    shim.session,
                    data.as_ptr() as CK_BYTE_PTR,
                    data.len() as CK_ULONG,
                    signature.as_mut_ptr(),
                    &mut sig_len,
                )
            },
            CKR_OK as CK_RV,
            "{abi:?} C_Sign"
        );

        // The genuine signature verifies.
        assert_eq!(
            unsafe { dispatch::general::c_verify_init(shim.session, &mut mechanism, key) },
            CKR_OK as CK_RV,
            "{abi:?} C_VerifyInit"
        );
        assert_eq!(
            unsafe {
                dispatch::general::c_verify(
                    shim.session,
                    data.as_ptr() as CK_BYTE_PTR,
                    data.len() as CK_ULONG,
                    signature.as_ptr() as CK_BYTE_PTR,
                    sig_len,
                )
            },
            CKR_OK as CK_RV,
            "{abi:?} genuine signature verifies through the proxy"
        );

        // A tampered signature is rejected — the loop actually checks.
        let mut tampered = signature.clone();
        tampered[0] ^= 0x01;
        assert_eq!(
            unsafe { dispatch::general::c_verify_init(shim.session, &mut mechanism, key) },
            CKR_OK as CK_RV,
        );
        assert_eq!(
            unsafe {
                dispatch::general::c_verify(
                    shim.session,
                    data.as_ptr() as CK_BYTE_PTR,
                    data.len() as CK_ULONG,
                    tampered.as_ptr() as CK_BYTE_PTR,
                    sig_len,
                )
            },
            CKR_SIGNATURE_INVALID as CK_RV,
            "{abi:?} a corrupted signature is rejected"
        );
    }
}

#[test]
fn generated_key_default_attributes_bridge_cross_abi() {
    // Synthesized CKA_CLASS/CKA_KEY_TYPE are ulong attributes, so they
    // must read back at the client width through the bridge on foreign
    // ABIs — a client reading a generated key sees an authentic object.
    let _guard = shim_state_test_guard();
    for abi in foreign_profiles() {
        let (_daemon, shim) = session_on(abi);
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_AES_KEY_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut key = CK_INVALID_HANDLE;
        let rv = unsafe {
            dispatch::general::c_generate_key(
                shim.session,
                &mut mechanism,
                std::ptr::null_mut(),
                0,
                &mut key,
            )
        };
        assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} C_GenerateKey");

        let w = std::mem::size_of::<CK_ULONG>();
        let mut class_buf = vec![0u8; w];
        let mut attr = CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: class_buf.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: w as CK_ULONG,
        };
        let rv =
            unsafe { dispatch::general::c_get_attribute_value(shim.session, key, &mut attr, 1) };
        assert_eq!(rv, CKR_OK as CK_RV, "{abi:?} read CKA_CLASS");
        let bytes: [u8; std::mem::size_of::<CK_ULONG>()] =
            class_buf.as_slice().try_into().expect("width");
        assert_eq!(CK_ULONG::from_le_bytes(bytes), CKO_SECRET_KEY as CK_ULONG, "{abi:?} CKA_CLASS");
    }
}

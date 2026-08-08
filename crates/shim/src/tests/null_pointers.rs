use super::*;

#[test]
fn c_init_token_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    let rv = unsafe {
        dispatch::general::c_init_token(0, std::ptr::null_mut(), 0, std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_init_pin_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    let rv = unsafe { dispatch::general::c_init_pin(0, std::ptr::null_mut(), 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_set_pin_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    let rv = unsafe {
        dispatch::general::c_set_pin(0, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0)
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_init_pin_rejects_unserializable_pin_length_before_client_use() {
    let _guard = shim_state_test_guard();
    let pin = std::ptr::dangling_mut::<CK_UTF8CHAR>();
    let rv = unsafe { dispatch::general::c_init_pin(0, pin, CK_ULONG::MAX) };
    assert_eq!(rv, CKR_GENERAL_ERROR as CK_RV);
}

#[test]
fn c_get_info_null_p_info_returns_bad_args() {
    let rv = unsafe { dispatch::general::c_get_info(std::ptr::null_mut()) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_get_slot_list_null_pul_count_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_get_slot_list(0, std::ptr::null_mut(), std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_get_slot_info_null_p_info_returns_bad_args() {
    let rv = unsafe { dispatch::general::c_get_slot_info(0, std::ptr::null_mut()) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_get_token_info_null_p_info_returns_bad_args() {
    let rv = unsafe { dispatch::general::c_get_token_info(0, std::ptr::null_mut()) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_get_mechanism_list_null_pul_count_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_get_mechanism_list(0, std::ptr::null_mut(), std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_get_mechanism_info_null_p_info_returns_bad_args() {
    let rv = unsafe { dispatch::general::c_get_mechanism_info(0, 0, std::ptr::null_mut()) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_open_session_null_ph_session_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_open_session(0, 0, std::ptr::null_mut(), None, std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_get_session_info_null_p_info_returns_bad_args() {
    let rv = unsafe { dispatch::general::c_get_session_info(0, std::ptr::null_mut()) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_find_objects_init_null_template_nonzero_count_returns_bad_args() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_find_objects_init(0, std::ptr::null_mut(), 5) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_create_object_null_template_nonzero_count_returns_bad_args() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let mut object = CK_INVALID_HANDLE;
    let rv = unsafe { dispatch::general::c_create_object(0, std::ptr::null_mut(), 5, &mut object) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_generate_key_null_template_nonzero_count_returns_bad_args() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut key = CK_INVALID_HANDLE;
    let rv = unsafe {
        dispatch::general::c_generate_key(0, &mut mechanism, std::ptr::null_mut(), 5, &mut key)
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_find_objects_init_null_attr_value_nonzero_len_returns_bad_args() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let mut attr = CK_ATTRIBUTE { type_: CKA_LABEL, pValue: std::ptr::null_mut(), ulValueLen: 1 };
    let rv = unsafe { dispatch::general::c_find_objects_init(0, &mut attr, 1) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_create_object_null_attr_value_nonzero_len_returns_bad_args() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let mut attr = CK_ATTRIBUTE { type_: CKA_LABEL, pValue: std::ptr::null_mut(), ulValueLen: 1 };
    let mut object = CK_INVALID_HANDLE;
    let rv = unsafe { dispatch::general::c_create_object(0, &mut attr, 1, &mut object) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_wait_for_slot_event_nonnull_reserved_returns_bad_args() {
    let _guard = shim_state_test_guard();
    let mut slot = 0;
    let mut reserved = 0u8;
    let rv = unsafe {
        dispatch::general::c_wait_for_slot_event(0, &mut slot, (&mut reserved as *mut u8).cast())
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_sign_init_null_mechanism_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_sign_init(0, std::ptr::null_mut(), 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_sign_null_pul_len_reaches_client_state() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe {
        dispatch::general::c_sign(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_sign_final_null_pul_len_reaches_client_state() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv =
        unsafe { dispatch::general::c_sign_final(0, std::ptr::null_mut(), std::ptr::null_mut()) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_verify_init_null_mechanism_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_verify_init(0, std::ptr::null_mut(), 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_sign_recover_init_null_mechanism_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_sign_recover_init(0, std::ptr::null_mut(), 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_verify_recover_init_null_mechanism_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_verify_recover_init(0, std::ptr::null_mut(), 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_sign_recover_null_pul_len_reaches_client_state() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe {
        dispatch::general::c_sign_recover(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_verify_recover_null_pul_len_reaches_client_state() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe {
        dispatch::general::c_verify_recover(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_digest_init_null_mechanism_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_digest_init(0, std::ptr::null_mut()) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_digest_null_pul_len_reaches_client_state() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe {
        dispatch::general::c_digest(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_encrypt_init_null_mechanism_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_encrypt_init(0, std::ptr::null_mut(), 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_encrypt_null_pul_len_reaches_client_state() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe {
        dispatch::general::c_encrypt(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_decrypt_init_null_mechanism_before_initialize_returns_not_initialized() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe { dispatch::general::c_decrypt_init(0, std::ptr::null_mut(), 0) };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_decrypt_null_pul_len_reaches_client_state() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe {
        dispatch::general::c_decrypt(
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

#[test]
fn c_find_objects_null_outputs_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_find_objects(0, std::ptr::null_mut(), 0, std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_get_attribute_value_null_template_returns_bad_args() {
    let rv = unsafe { dispatch::general::c_get_attribute_value(0, 0, std::ptr::null_mut(), 1) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_create_object_null_ph_object_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_create_object(0, std::ptr::null_mut(), 0, std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_generate_key_pair_null_outputs_returns_bad_args() {
    let rv = unsafe {
        dispatch::general::c_generate_key_pair(
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_generate_random_null_returns_bad_args() {
    let rv = unsafe { dispatch::general::c_generate_random(0, std::ptr::null_mut(), 32) };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_generate_random_null_precedes_unrepresentable_length() {
    if CK_ULONG::BITS <= u32::BITS {
        return;
    }

    let too_large = (u32::MAX as u64 + 1) as CK_ULONG;
    let rv = unsafe { dispatch::general::c_generate_random(0, std::ptr::null_mut(), too_large) };

    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_generate_random_rejects_length_above_wire_width_before_client_use() {
    if CK_ULONG::BITS <= u32::BITS {
        return;
    }

    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let output = std::ptr::dangling_mut::<CK_BYTE>();
    let too_large = (u32::MAX as u64 + 1) as CK_ULONG;

    let rv = unsafe { dispatch::general::c_generate_random(0, output, too_large) };

    assert_eq!(rv, CKR_DATA_LEN_RANGE as CK_RV);
}

#[test]
fn c_wrap_key_null_mechanism_still_precedes_client_state() {
    let rv = unsafe {
        dispatch::general::c_wrap_key(
            0,
            std::ptr::null_mut(),
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
}

#[test]
fn c_get_operation_state_null_pul_len_reaches_client_state() {
    let _guard = shim_state_test_guard();
    state::mark_finalized();
    let rv = unsafe {
        dispatch::general::c_get_operation_state(0, std::ptr::null_mut(), std::ptr::null_mut())
    };
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV);
}

// ---------------------------------------------------------------------------
// ADR-0010 Scope 2: NULL-pointer faithfulness end-to-end (c_decrypt exemplar)
//
// These tests require a full shim → client → gRPC → server → MockBackend
// stack and so need a running daemon. They use their own minimal fixture
// rather than the one in output_semantics.rs (which is private).
// ---------------------------------------------------------------------------

mod decrypt_null_e2e {
    use std::sync::Arc;
    use std::time::Duration;

    use pkcs11_proxy_ng::server::context_manager::ContextManager;
    use pkcs11_proxy_ng::server::grpc_service::Pkcs11ProxyService;
    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
    use pkcs11_proxy_ng_proto::Pkcs11ProxyServer;
    use pkcs11_proxy_ng_types::{CkMechanismType, CkSlotId, InterfaceCapabilities, InterfaceInfo};
    use tokio::net::TcpListener;
    use tokio::runtime::Runtime;
    use tokio::sync::watch;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;

    use super::super::*;

    /// A minimal in-process daemon for c_decrypt e2e tests.
    struct DecryptDaemon {
        // Kept to ensure the tokio runtime outlives the daemon.
        _runtime: Runtime,
        endpoint: String,
        _shutdown: watch::Sender<bool>,
    }

    impl DecryptDaemon {
        fn start() -> Self {
            let runtime = Runtime::new().expect("test runtime");
            let (endpoint, shutdown_tx) = runtime.block_on(async {
                let backend = Arc::new(MockBackend::new(
                    vec![CkSlotId(0)],
                    vec![CkMechanismType::AES_ECB, CkMechanismType::AES_GCM],
                ));
                backend.set_interface_capabilities(InterfaceCapabilities {
                    interfaces: vec![
                        InterfaceInfo {
                            version_major: 2,
                            version_minor: 40,
                            null_functions: vec![],
                        },
                        InterfaceInfo {
                            version_major: 3,
                            version_minor: 0,
                            null_functions: vec![],
                        },
                        InterfaceInfo {
                            version_major: 3,
                            version_minor: 2,
                            null_functions: vec![],
                        },
                    ],
                });
                let backend_trait: Arc<dyn Pkcs11Backend> = backend.clone();
                let context_manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
                context_manager.populate_slots(&backend_trait).await.expect("populate_slots");

                let service =
                    Pkcs11ProxyService::insecure_for_tests(context_manager.clone(), backend_trait);
                let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
                let addr = listener.local_addr().expect("local addr");
                let endpoint = format!("http://127.0.0.1:{}", addr.port());
                let incoming = TcpListenerStream::new(listener);
                let (shutdown_tx, shutdown_rx) = watch::channel(false);
                tokio::spawn(async move {
                    let _ = Server::builder()
                        .add_service(Pkcs11ProxyServer::new(service))
                        .serve_with_incoming_shutdown(incoming, async move {
                            let mut shutdown_rx = shutdown_rx;
                            let _ = shutdown_rx.changed().await;
                        })
                        .await;
                });
                tokio::time::sleep(Duration::from_millis(50)).await;
                (endpoint, shutdown_tx)
            });
            Self { _runtime: runtime, endpoint, _shutdown: shutdown_tx }
        }
    }

    impl Drop for DecryptDaemon {
        fn drop(&mut self) {
            let _ = unsafe { dispatch::general::c_finalize(std::ptr::null_mut()) };
            unsafe { std::env::remove_var("PKCS11_PROXY_ENDPOINT") };
        }
    }

    fn aes_ecb_mechanism() -> CK_MECHANISM {
        CK_MECHANISM { mechanism: CKM_AES_ECB, pParameter: std::ptr::null_mut(), ulParameterLen: 0 }
    }

    /// Open a shim session against the daemon, create a key object, and run
    /// C_DecryptInit. Returns the session handle and the key object handle.
    fn init_decrypt_session(endpoint: &str) -> (CK_SESSION_HANDLE, CK_OBJECT_HANDLE) {
        unsafe {
            std::env::set_var("PKCS11_PROXY_ENDPOINT", endpoint);
        }
        let rv = unsafe { dispatch::general::c_initialize(std::ptr::null_mut()) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_Initialize");

        let mut slot_count: CK_ULONG = 0;
        let rv = unsafe {
            dispatch::general::c_get_slot_list(CK_FALSE, std::ptr::null_mut(), &mut slot_count)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "GetSlotList count");
        assert!(slot_count > 0);

        let mut slots = vec![0 as CK_SLOT_ID; slot_count as usize];
        let rv = unsafe {
            dispatch::general::c_get_slot_list(CK_FALSE, slots.as_mut_ptr(), &mut slot_count)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "GetSlotList data");

        let mut session = CK_INVALID_HANDLE;
        let rv = unsafe {
            dispatch::general::c_open_session(
                slots[0],
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                None,
                &mut session,
            )
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_OpenSession");

        // Create a key object (mock accepts any object as a key)
        let mut key = CK_INVALID_HANDLE;
        let rv = unsafe {
            dispatch::general::c_create_object(session, std::ptr::null_mut(), 0, &mut key)
        };
        assert_eq!(rv, CKR_OK as CK_RV, "C_CreateObject");

        // Initialize decrypt
        let mut mech = aes_ecb_mechanism();
        let rv = unsafe { dispatch::general::c_decrypt_init(session, &mut mech, key) };
        assert_eq!(rv, CKR_OK as CK_RV, "C_DecryptInit");

        (session, key)
    }

    /// ADR-0010 Scope 2: NULL input pointer with non-zero len reaches the
    /// MockBackend as `CkInBuf::Null{len}`. MockBackend rejects that with
    /// ARGUMENTS_BAD (strict-token policy), proving the NULL-ness crossed the
    /// full shim → client → server → backend path.
    #[test]
    fn c_decrypt_null_input_with_len_reaches_backend_as_null() {
        let _guard = shim_state_test_guard();
        let daemon = DecryptDaemon::start();
        let (session, _key) = init_decrypt_session(&daemon.endpoint);

        let mut out_len: CK_ULONG = 64;
        let mut out_buf = vec![0u8; 64];
        // NULL input pointer, non-zero claimed length.
        let rv = unsafe {
            dispatch::general::c_decrypt(
                session,
                std::ptr::null_mut(), // NULL input
                16,                   // claimed len > 0
                out_buf.as_mut_ptr(),
                &mut out_len,
            )
        };
        // MockBackend returns ARGUMENTS_BAD for Null{len>0}, proving NULL-ness
        // crossed the full shim → client → server → backend path.
        assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
    }

    /// ADR-0010 Scope 2: TooLarge input is caught by the shim itself (transport
    /// limit RV) and never reaches the daemon. Previously this would panic
    /// (GENERAL_ERROR); now it returns the documented stable RV (ARGUMENTS_BAD).
    #[test]
    fn c_decrypt_too_large_input_shim_rejects_with_arguments_bad() {
        let _guard = shim_state_test_guard();
        let daemon = DecryptDaemon::start();
        let (session, _key) = init_decrypt_session(&daemon.endpoint);

        let mut out_len: CK_ULONG = 64;
        let mut out_buf = vec![0u8; 64];
        // Valid (non-null) pointer but unmaterializable length.
        let dangling: *mut CK_BYTE = std::ptr::dangling_mut::<CK_BYTE>();
        let rv = unsafe {
            dispatch::general::c_decrypt(
                session,
                dangling,
                CK_ULONG::MAX, // TooLarge
                out_buf.as_mut_ptr(),
                &mut out_len,
            )
        };
        assert_eq!(rv, CKR_ARGUMENTS_BAD as CK_RV);
    }

    /// ADR-0010 Scope 2 negative control: NULL pointer + len=0 is a valid
    /// "empty input" (Null{len:0}). The MockBackend treats it as an empty
    /// slice and returns OK (or BUFFER_TOO_SMALL on size query) — it must NOT
    /// return ARGUMENTS_BAD from the null-input handler, confirming that only
    /// Null{len>0} triggers the rejection.
    #[test]
    fn c_decrypt_null_input_zero_len_is_not_arguments_bad_from_null_handling() {
        let _guard = shim_state_test_guard();
        let daemon = DecryptDaemon::start();
        let (session, _key) = init_decrypt_session(&daemon.endpoint);

        let mut out_len: CK_ULONG = 64;
        let mut out_buf = vec![0u8; 64];
        // NULL input pointer with zero len — treated as empty, not as an error
        // from our NULL-faithfulness code.
        let rv = unsafe {
            dispatch::general::c_decrypt(
                session,
                std::ptr::null_mut(), // NULL input
                0,                    // len == 0, so Null{len:0}
                out_buf.as_mut_ptr(),
                &mut out_len,
            )
        };
        // NULL input + zero len = empty = mock returns CKR_OK.
        assert_eq!(rv, CKR_OK as CK_RV);
    }
}

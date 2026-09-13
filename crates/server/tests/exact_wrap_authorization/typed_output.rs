use super::*;

// Break caught: a server still accepting old pointer-bearing requests or
// serializing backend input handles into authenticated output.
#[tokio::test]
async fn authenticated_typed_server_negotiates_all_three_routes_without_raw_output() {
    let f = fixture(grant()).await;
    let mut c = open(&f, false).await;
    for typed in [false, true] {
        for route in 0..3 {
            let before = f.backend.wrap_observations().len();
            let parameters = typed.then(AuthenticatedParameters::default);
            let (rv, raw_empty, ack) = match route {
                0 => {
                    let r = c
                        .rpc
                        .wrap_key_authenticated(WrapKeyAuthenticatedRequest {
                            client_context_id: c.context.clone(),
                            session_handle: c.session,
                            mechanism: mechanism(c.keys[2]),
                            wrapping_key_handle: c.keys[0],
                            key_handle: c.keys[1],
                            authenticated_parameters: parameters,
                            ..Default::default()
                        })
                        .await
                        .unwrap()
                        .into_inner();
                    (r.ck_rv, r.mechanism_parameter_out.is_empty(), r.authenticated_output)
                }
                1 => {
                    let r = c
                        .rpc
                        .parameter_output_exact(ParameterOutputExactRequest {
                            client_context_id: c.context.clone(),
                            session_handle: c.session,
                            mechanism: mechanism(c.keys[2]),
                            wrapping_key_handle: c.keys[0],
                            key_handle: c.keys[1],
                            function: ParameterOutputFunction::WrapKeyAuthenticated as i32,
                            output_spec: Some(output_spec()),
                            authenticated_parameters: parameters,
                            ..Default::default()
                        })
                        .await
                        .unwrap()
                        .into_inner();
                    (
                        r.output_result.unwrap().ck_rv,
                        r.parameter_result
                            .as_ref()
                            .is_none_or(|p| p.value.as_ref().is_none_or(Vec::is_empty)),
                        r.authenticated_output,
                    )
                }
                _ => {
                    let r = c
                        .rpc
                        .unwrap_key_authenticated(UnwrapKeyAuthenticatedRequest {
                            client_context_id: c.context.clone(),
                            session_handle: c.session,
                            mechanism: mechanism(c.keys[2]),
                            unwrapping_key_handle: c.keys[0],
                            wrapped_key: vec![0; 16],
                            authenticated_parameters: parameters,
                            ..Default::default()
                        })
                        .await
                        .unwrap()
                        .into_inner();
                    (r.ck_rv, r.mechanism_parameter_out.is_empty(), r.authenticated_output)
                }
            };
            assert_eq!(
                rv,
                if typed { CkRv::OK.0 } else { CkRv::FUNCTION_NOT_SUPPORTED.0 },
                "route {route} typed {typed}"
            );
            assert!(raw_empty, "native-structure output channel must be empty");
            if typed {
                assert!(matches!(
                    ack.and_then(|a| a.output),
                    Some(authenticated_mechanism_output::Output::Unchanged(true))
                ));
            } else {
                assert!(ack.is_none());
            }
            assert_eq!(f.backend.wrap_observations().len() - before, usize::from(typed));
        }
    }
}

#[tokio::test]
async fn authenticated_typed_server_advertises_pre_call_capability() {
    let f = fixture(grant()).await;
    let mut c = open(&f, false).await;
    let caps = c
        .rpc
        .get_backend_interfaces(GetBackendInterfacesRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(caps.pointer_safe_authenticated_parameters, Some(true));
}

#[tokio::test]
async fn authenticated_typed_sdk_roundtrips_ordinary_exact_and_unwrap_over_mtls() {
    use pkcs11_proxy_ng_client::Pkcs11Client;
    use pkcs11_proxy_ng_proto::convert::authenticated::AuthenticatedOutput;
    let f = fixture(grant()).await;
    let mut client =
        Pkcs11Client::connect_with_tls_files(&f.endpoint, f.client_a.clone()).await.unwrap();
    client.initialize().await.unwrap();
    let slot = client.get_slot_list(true).await.unwrap()[0];
    let session = client
        .open_session(
            slot,
            CkSessionFlags(CkSessionFlags::RW_SESSION | CkSessionFlags::SERIAL_SESSION),
        )
        .await
        .unwrap();
    let key = client.create_object(session, &[]).await.unwrap();
    let mechanism = CkMechanism {
        mechanism_type: CkMechanismType::GOSTR3410_KEY_WRAP,
        params: Some(CkMechanismParams::Gostr3410KeyWrap(Gostr3410KeyWrapParams {
            wrap_oid: vec![1; 3],
            ukm: vec![2; 8],
            key_handle: key.0,
        })),
    };
    let (wrapped, output) = client
        .wrap_key_authenticated_typed(session, &mechanism, None, key, key, CkInBuf::Bytes(&[]))
        .await
        .unwrap();
    assert!(matches!(output, AuthenticatedOutput::Unchanged));
    for (present, capacity, expected) in
        [(false, 0, CkRv::OK), (true, 0, CkRv::BUFFER_TOO_SMALL), (true, 128, CkRv::OK)]
    {
        let (main, output) = client
            .wrap_key_authenticated_exact_typed(
                session,
                &mechanism,
                None,
                key,
                key,
                CkInBuf::Bytes(&[]),
                &CkOutputBufferSpec {
                    buffer_present: present,
                    buffer_len: capacity,
                    length_pointer_null: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(main.ck_rv, expected);
        assert!(matches!(output, AuthenticatedOutput::Unchanged));
    }
    let (unwrapped, output) = client
        .unwrap_key_authenticated_typed(
            session,
            &mechanism,
            None,
            key,
            CkInBuf::Bytes(&wrapped),
            &[],
            CkInBuf::Bytes(&[]),
        )
        .await
        .unwrap();
    assert_ne!(unwrapped.0, 0);
    assert!(matches!(output, AuthenticatedOutput::Unchanged));
    client.finalize().await.unwrap();
}

#[tokio::test]
async fn authenticated_typed_exact_rejects_dual_raw_request_before_dispatch() {
    let f = fixture(grant()).await;
    let mut c = open(&f, false).await;
    let before = f.backend.wrap_observations().len();
    let response = c
        .rpc
        .parameter_output_exact(ParameterOutputExactRequest {
            client_context_id: c.context.clone(),
            session_handle: c.session,
            mechanism: mechanism(c.keys[2]),
            wrapping_key_handle: c.keys[0],
            key_handle: c.keys[1],
            function: ParameterOutputFunction::WrapKeyAuthenticated as i32,
            authenticated_parameters: Some(AuthenticatedParameters::default()),
            parameter: vec![0; 16],
            output_spec: Some(output_spec()),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.output_result.unwrap().ck_rv, CkRv::MECHANISM_PARAM_INVALID.0);
    assert!(response.authenticated_output.is_none());
    assert_eq!(f.backend.wrap_observations().len(), before);
}

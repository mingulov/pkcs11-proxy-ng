//! gRPC handlers for PKCS#11 3.2 KEM operations (Wave 2).
//!
//! - `C_EncapsulateKey`
//! - `C_DecapsulateKey`

use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_types::{CkObjectHandle, CkOutputBufferSpec, CkRv};

use super::super::convert_template;
use super::super::mechanism_handles::remap_mechanism_handles;
use super::super::service_utils::{
    check_sanitize, input_from_wire, parse_mechanism, register_session_object_handle,
    resolve_session_and_key, spawn_backend, template_declares_token_object,
};
use crate::server::context_manager::ClientContextId;
use crate::server::handle_map::VirtualHandle;

use crate::server::grpc_service::HandlerContext;
pub(crate) async fn encapsulate_key(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::EncapsulateKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::EncapsulateKeyResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, public_key) = match resolve_session_and_key(
        ctx,
        &ctx_id,
        req.session_handle,
        req.public_key_handle,
    )
    .await
    {
        Ok(handles) => handles,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyResponse {
                ck_rv: rv.0,
                ciphertext: Vec::new(),
                key_handle: 0,
            }));
        }
    };

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyResponse {
                ck_rv: rv.0,
                ciphertext: Vec::new(),
                key_handle: 0,
            }));
        }
    };

    // B1: remap object handles embedded in the mechanism parameters;
    // gate each through per-object authz when active (C1).
    if let Err(rv) =
        remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyResponse {
            ck_rv: rv.0,
            ciphertext: Vec::new(),
            key_handle: 0,
        }));
    }

    let template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyResponse {
                ck_rv: rv,
                ciphertext: Vec::new(),
                key_handle: 0,
            }));
        }
    };

    // An encapsulated key is a session object unless CKA_TOKEN is set (B2).
    let is_token = template_declares_token_object(&template);
    let virtual_session = VirtualHandle(req.session_handle);
    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.encapsulate_key(session, &mechanism, public_key, &template))
            .await?;

    match result {
        Ok((ciphertext, key)) => {
            let key_handle = register_session_object_handle(
                ctx_mgr,
                &ctx_id,
                virtual_session,
                CkObjectHandle(key.0 as u64),
                is_token,
            )
            .await;
            Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyResponse {
                ck_rv: CkRv::OK.0,
                ciphertext,
                key_handle,
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyResponse {
            ck_rv: error.0,
            ciphertext: Vec::new(),
            key_handle: 0,
        })),
    }
}

pub(crate) async fn decapsulate_key(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DecapsulateKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecapsulateKeyResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, private_key) =
        match resolve_session_and_key(ctx, &ctx_id, req.session_handle, req.private_key_handle)
            .await
        {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
                    ck_rv: rv.0,
                    key_handle: 0,
                }));
            }
        };

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
                ck_rv: rv.0,
                key_handle: 0,
            }));
        }
    };

    // B1: remap object handles embedded in the mechanism parameters;
    // gate each through per-object authz when active (C1).
    if let Err(rv) =
        remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
            ck_rv: rv.0,
            key_handle: 0,
        }));
    }

    let template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
                ck_rv: rv,
                key_handle: 0,
            }));
        }
    };

    // A decapsulated key is a session object unless CKA_TOKEN is set (B2).
    let is_token = template_declares_token_object(&template);
    let virtual_session = VirtualHandle(req.session_handle);
    let ciphertext = req.ciphertext;
    let ciphertext_null_len = req.ciphertext_null_len;
    // ADR-0010 sanitize_inputs: validate NULL ciphertext pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, ciphertext_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
            ck_rv: rv.0,
            key_handle: 0,
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.decapsulate_key(
            session,
            &mechanism,
            private_key,
            &template,
            input_from_wire(&ciphertext, ciphertext_null_len),
        )
    })
    .await?;

    match result {
        Ok(key) => {
            let key_handle = register_session_object_handle(
                ctx_mgr,
                &ctx_id,
                virtual_session,
                CkObjectHandle(key.0 as u64),
                is_token,
            )
            .await;
            Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
                ck_rv: CkRv::OK.0,
                key_handle,
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
            ck_rv: error.0,
            key_handle: 0,
        })),
    }
}

pub(crate) async fn encapsulate_key_exact(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::EncapsulateKeyExactRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, public_key) = match resolve_session_and_key(
        ctx,
        &ctx_id,
        req.session_handle,
        req.public_key_handle,
    )
    .await
    {
        Ok(handles) => handles,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse {
                result: Some(pkcs11_proxy_ng_proto::OutputAndHandleResult {
                    ck_rv: rv.0,
                    returned_len: 0,
                    value: None,
                    object_handle: 0,
                }),
            }));
        }
    };

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse {
                result: Some(pkcs11_proxy_ng_proto::OutputAndHandleResult {
                    ck_rv: rv.0,
                    returned_len: 0,
                    value: None,
                    object_handle: 0,
                }),
            }));
        }
    };

    // B1: remap object handles embedded in the mechanism parameters;
    // gate each through per-object authz when active (C1).
    if let Err(rv) =
        remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse {
            result: Some(pkcs11_proxy_ng_proto::OutputAndHandleResult {
                ck_rv: rv.0,
                returned_len: 0,
                value: None,
                object_handle: 0,
            }),
        }));
    }

    let template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse {
                result: Some(pkcs11_proxy_ng_proto::OutputAndHandleResult {
                    ck_rv: rv,
                    returned_len: 0,
                    value: None,
                    object_handle: 0,
                }),
            }));
        }
    };

    let spec =
        req.output_spec.as_ref().map(CkOutputBufferSpec::from).unwrap_or(CkOutputBufferSpec {
            buffer_present: false,
            buffer_len: 0,
            length_pointer_null: false,
        });

    // The exact-encapsulated key is a session object unless CKA_TOKEN is set (B2).
    let is_token = template_declares_token_object(&template);
    let virtual_session = VirtualHandle(req.session_handle);
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.encapsulate_key_exact(session, &mechanism, public_key, &template, &spec)
    })
    .await?;

    match result {
        Ok(r) => {
            // Register the returned object handle through the context manager
            let virtual_handle = if r.ck_rv == CkRv::OK && r.object_handle.0 != 0 {
                register_session_object_handle(
                    ctx_mgr,
                    &ctx_id,
                    virtual_session,
                    r.object_handle,
                    is_token,
                )
                .await
            } else {
                0
            };
            Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse {
                result: Some(pkcs11_proxy_ng_proto::OutputAndHandleResult {
                    ck_rv: r.ck_rv.0,
                    returned_len: r.returned_len,
                    value: r.value,
                    object_handle: virtual_handle,
                }),
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse {
            result: Some(pkcs11_proxy_ng_proto::OutputAndHandleResult {
                ck_rv: error.0,
                returned_len: 0,
                value: None,
                object_handle: 0,
            }),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
    use pkcs11_proxy_ng_types::{CkMechanismType, CkSessionFlags, CkSlotId};

    use crate::server::context_manager::ContextManager;
    use crate::server::grpc_service::service_utils::{
        register_session_handle, register_session_object_handle,
    };

    #[tokio::test]
    async fn missing_output_length_is_forwarded_to_kem_backend() {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        mock.initialize().unwrap();
        let backend_session =
            mock.open_session(CkSlotId(0), CkSessionFlags(CkSessionFlags::SERIAL_SESSION)).unwrap();
        let public_key = mock.create_object(backend_session, &[]).unwrap();
        let backend: Arc<dyn Pkcs11Backend> = mock;
        let manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        manager.register_slot(CkSlotId(0)).await;
        let context_id = manager.create_context(None).await.unwrap();
        let virtual_session =
            register_session_handle(&manager, &context_id, backend_session, CkSlotId(0))
                .await
                .unwrap();
        let virtual_session = VirtualHandle(virtual_session);
        let virtual_public_key = register_session_object_handle(
            &manager,
            &context_id,
            virtual_session,
            public_key,
            false,
        )
        .await;

        let result = encapsulate_key_exact(
            &HandlerContext::for_test(&manager, &backend),
            Request::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactRequest {
                client_context_id: context_id.0,
                session_handle: virtual_session.0,
                mechanism: Some(pkcs11_proxy_ng_proto::Mechanism {
                    mechanism_type: CkMechanismType::RSA_PKCS.0,
                    params: None,
                }),
                public_key_handle: virtual_public_key,
                template: Vec::new(),
                output_spec: Some(pkcs11_proxy_ng_proto::OutputBufferSpec {
                    buffer_present: true,
                    buffer_len: 0,
                    length_pointer_null: true,
                }),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();

        assert_eq!(result.ck_rv, CkRv::ARGUMENTS_BAD.0);
        assert_eq!(result.returned_len, 0);
        assert_eq!(result.value, None);
        assert_eq!(result.object_handle, 0);
    }
}

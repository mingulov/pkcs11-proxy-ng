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

    // B1: remap object handles embedded in the mechanism parameters.
    if let Err(rv) = remap_mechanism_handles(ctx_mgr, &ctx_id, &mut mechanism).await {
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

    // B1: remap object handles embedded in the mechanism parameters.
    if let Err(rv) = remap_mechanism_handles(ctx_mgr, &ctx_id, &mut mechanism).await {
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

    // B1: remap object handles embedded in the mechanism parameters.
    if let Err(rv) = remap_mechanism_handles(ctx_mgr, &ctx_id, &mut mechanism).await {
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

    let spec = req
        .output_spec
        .as_ref()
        .map(|s| CkOutputBufferSpec { buffer_present: s.buffer_present, buffer_len: s.buffer_len })
        .unwrap_or(CkOutputBufferSpec { buffer_present: false, buffer_len: 0 });

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

use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::{CkMechanismParams, CkObjectHandle, CkRv, Sp800108DerivedKey};

use super::super::convert_template;
use super::super::service_utils::{
    parse_mechanism, register_object_handle, register_object_pair, resolve_session,
    resolve_session_and_object, spawn_backend,
};
use crate::server::context_manager::{ClientContextId, ContextManager};
use crate::server::handle_map::VirtualHandle;

const CK_SP800_108_KEY_HANDLE: u64 = 0x0000_0005;

pub(crate) async fn generate_key_pair(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GenerateKeyPairRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GenerateKeyPairResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
                ck_rv: rv.0,
                public_key_handle: 0,
                private_key_handle: 0,
            }));
        }
    };

    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
                ck_rv: rv.0,
                public_key_handle: 0,
                private_key_handle: 0,
            }));
        }
    };

    let public_key_template = match convert_template(&req.public_key_template) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
                ck_rv: rv,
                public_key_handle: 0,
                private_key_handle: 0,
            }));
        }
    };

    let private_key_template = match convert_template(&req.private_key_template) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
                ck_rv: rv,
                public_key_handle: 0,
                private_key_handle: 0,
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.generate_key_pair(session, &mechanism, &public_key_template, &private_key_template)
    })
    .await?;

    match result {
        Ok((public_key, private_key)) => {
            let virtual_handles = register_object_pair(
                ctx_mgr,
                &ctx_id,
                CkObjectHandle(public_key.0),
                CkObjectHandle(private_key.0),
            )
            .await;
            match virtual_handles {
                Some((public_key_handle, private_key_handle)) => {
                    Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
                        ck_rv: CkRv::OK.0,
                        public_key_handle,
                        private_key_handle,
                    }))
                }
                None => Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
                    ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
                    public_key_handle: 0,
                    private_key_handle: 0,
                })),
            }
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyPairResponse {
            ck_rv: error.0,
            public_key_handle: 0,
            private_key_handle: 0,
        })),
    }
}

pub(crate) async fn generate_key(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GenerateKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GenerateKeyResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyResponse {
                ck_rv: rv.0,
                key_handle: 0,
            }));
        }
    };

    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyResponse {
                ck_rv: rv.0,
                key_handle: 0,
            }));
        }
    };

    let template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyResponse {
                ck_rv: rv,
                key_handle: 0,
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.generate_key(session, &mechanism, &template)).await?;

    match result {
        Ok(object) => {
            let key_handle =
                register_object_handle(ctx_mgr, &ctx_id, CkObjectHandle(object.0)).await;
            Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyResponse {
                ck_rv: CkRv::OK.0,
                key_handle,
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::GenerateKeyResponse {
            ck_rv: error.0,
            key_handle: 0,
        })),
    }
}

pub(crate) async fn derive_key(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::DeriveKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DeriveKeyResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, base_key) =
        match resolve_session_and_object(ctx_mgr, &ctx_id, req.session_handle, req.base_key_handle)
            .await
        {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
                    ck_rv: rv.0,
                    key_handle: 0,
                    mechanism_out: None,
                }));
            }
        };

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
                ck_rv: rv.0,
                key_handle: 0,
                mechanism_out: None,
            }));
        }
    };

    // CKM_CONCATENATE_BASE_AND_KEY passes an object handle inside the
    // mechanism parameter.  Translate the client's virtual handle to the
    // backend's real handle so the backend can resolve it.
    if let Some(pkcs11_proxy_ng_types::CkMechanismParams::ObjectHandle(ref mut p)) =
        mechanism.params
    {
        let resolved = ctx_mgr
            .get_context(&ctx_id, |ctx| ctx.object_handles.resolve(VirtualHandle(p.handle)))
            .await;
        match resolved {
            Some(Some(backend_handle)) => {
                p.handle = backend_handle.0;
            }
            _ => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
                    ck_rv: CkRv::OBJECT_HANDLE_INVALID.0,
                    key_handle: 0,
                    mechanism_out: None,
                }));
            }
        }
    }

    if let Some(ref mut params) = mechanism.params
        && let Err(rv) = resolve_sp800_108_key_handle_data_params(ctx_mgr, &ctx_id, params).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
            ck_rv: rv.0,
            key_handle: 0,
            mechanism_out: None,
        }));
    }

    let template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
                ck_rv: rv,
                key_handle: 0,
                mechanism_out: None,
            }));
        }
    };

    let mechanism_type = mechanism.mechanism_type;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.derive_key_with_output_result(session, &mechanism, base_key, &template)
    })
    .await?;

    match result {
        Ok(mut derive_result) => {
            let key_handle = if derive_result.rv.is_ok() {
                match derive_result.key_handle {
                    Some(object) => register_object_handle(ctx_mgr, &ctx_id, object).await,
                    None => 0,
                }
            } else {
                0
            };
            if derive_result.rv.is_ok()
                && let Some(ref mut params) = derive_result.mechanism_out
            {
                virtualize_sp800_108_additional_handles(ctx_mgr, &ctx_id, params).await;
            }
            let mechanism_out = derive_result.mechanism_out.map(|params| {
                pkcs11_proxy_ng_proto::Mechanism::from(&pkcs11_proxy_ng_types::CkMechanism {
                    mechanism_type,
                    params: Some(params),
                })
            });
            Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
                ck_rv: derive_result.rv.0,
                key_handle,
                mechanism_out,
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
            ck_rv: error.0,
            key_handle: 0,
            mechanism_out: None,
        })),
    }
}

async fn resolve_sp800_108_key_handle_data_params(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    params: &mut CkMechanismParams,
) -> Result<(), CkRv> {
    match params {
        CkMechanismParams::Sp800108Kdf(params) => {
            resolve_sp800_108_key_handle_data_param_list(ctx_mgr, ctx_id, &mut params.data_params)
                .await
        }
        CkMechanismParams::Sp800108FeedbackKdf(params) => {
            resolve_sp800_108_key_handle_data_param_list(ctx_mgr, ctx_id, &mut params.data_params)
                .await
        }
        _ => Ok(()),
    }
}

async fn resolve_sp800_108_key_handle_data_param_list(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    data_params: &mut [pkcs11_proxy_ng_types::PrfDataParam],
) -> Result<(), CkRv> {
    for data_param in data_params {
        if data_param.type_ != CK_SP800_108_KEY_HANDLE {
            continue;
        }

        let (virtual_handle, width) = read_sp800_108_key_handle_value(&data_param.value)?;
        let backend_handle = ctx_mgr
            .get_context(ctx_id, |ctx| ctx.object_handles.resolve(VirtualHandle(virtual_handle)))
            .await
            .and_then(|resolved| resolved)
            .ok_or(CkRv::OBJECT_HANDLE_INVALID)?;
        data_param.value = write_sp800_108_key_handle_value(backend_handle.0, width)?;
    }
    Ok(())
}

fn read_sp800_108_key_handle_value(value: &[u8]) -> Result<(u64, usize), CkRv> {
    match value.len() {
        8 => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(value);
            Ok((u64::from_ne_bytes(bytes), 8))
        }
        4 => {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(value);
            Ok((u32::from_ne_bytes(bytes) as u64, 4))
        }
        _ => Err(CkRv::MECHANISM_PARAM_INVALID),
    }
}

fn write_sp800_108_key_handle_value(handle: u64, width: usize) -> Result<Vec<u8>, CkRv> {
    match width {
        8 => Ok(handle.to_ne_bytes().to_vec()),
        4 => Ok(u32::try_from(handle)
            .map_err(|_| CkRv::OBJECT_HANDLE_INVALID)?
            .to_ne_bytes()
            .to_vec()),
        _ => Err(CkRv::MECHANISM_PARAM_INVALID),
    }
}

async fn virtualize_sp800_108_additional_handles(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    params: &mut CkMechanismParams,
) {
    match params {
        CkMechanismParams::Sp800108Kdf(params) => {
            virtualize_derived_key_handles(ctx_mgr, ctx_id, &mut params.additional_derived_keys)
                .await;
        }
        CkMechanismParams::Sp800108FeedbackKdf(params) => {
            virtualize_derived_key_handles(ctx_mgr, ctx_id, &mut params.additional_derived_keys)
                .await;
        }
        _ => {}
    }
}

async fn virtualize_derived_key_handles(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    derived_keys: &mut [Sp800108DerivedKey],
) {
    for derived_key in derived_keys {
        if derived_key.key_handle != 0 {
            derived_key.key_handle =
                register_object_handle(ctx_mgr, ctx_id, CkObjectHandle(derived_key.key_handle))
                    .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::server::handle_map::BackendHandle;
    use pkcs11_proxy_ng_types::{
        CkMechanismType, PrfDataParam, Sp800108FeedbackKdfParams, Sp800108KdfParams,
    };

    #[tokio::test]
    async fn resolves_sp800_108_key_handle_data_param_to_backend_handle_bytes() {
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 16));
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let backend_key = BackendHandle(0xABCD_0102);
        let virtual_key = ctx_mgr
            .get_context(&ctx_id, |ctx| ctx.object_handles.insert(backend_key))
            .await
            .unwrap();
        let mut params = CkMechanismParams::Sp800108FeedbackKdf(Sp800108FeedbackKdfParams {
            prf_type: CkMechanismType::SHA256.0,
            data_params: vec![PrfDataParam {
                type_: CK_SP800_108_KEY_HANDLE,
                value: virtual_key.0.to_ne_bytes().to_vec(),
            }],
            iv: vec![0xA5; 16],
            additional_derived_keys: Vec::new(),
        });

        resolve_sp800_108_key_handle_data_params(&ctx_mgr, &ctx_id, &mut params).await.unwrap();

        let CkMechanismParams::Sp800108FeedbackKdf(params) = params else {
            panic!("expected SP800-108 feedback KDF params");
        };
        assert_eq!(params.data_params[0].value, backend_key.0.to_ne_bytes().to_vec());
    }

    #[tokio::test]
    async fn rejects_malformed_sp800_108_key_handle_data_param_width() {
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 16));
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let mut params = CkMechanismParams::Sp800108Kdf(Sp800108KdfParams {
            prf_type: CkMechanismType::SHA256.0,
            data_params: vec![PrfDataParam {
                type_: CK_SP800_108_KEY_HANDLE,
                value: vec![1, 2, 3],
            }],
            additional_derived_keys: Vec::new(),
        });

        let err = resolve_sp800_108_key_handle_data_params(&ctx_mgr, &ctx_id, &mut params)
            .await
            .unwrap_err();

        assert_eq!(err, CkRv::MECHANISM_PARAM_INVALID);
    }
}

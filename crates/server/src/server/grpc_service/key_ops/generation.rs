use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::{CkObjectHandle, CkRv};

use super::super::convert_template;
use super::super::service_utils::{
    parse_mechanism, register_object_handle, register_object_pair, resolve_session,
    resolve_session_and_object, spawn_backend,
};
use crate::server::context_manager::{ClientContextId, ContextManager};
use crate::server::handle_map::VirtualHandle;

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
                }));
            }
        };

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
                ck_rv: rv.0,
                key_handle: 0,
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
                }));
            }
        }
    }

    let template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
                ck_rv: rv,
                key_handle: 0,
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.derive_key(session, &mechanism, base_key, &template)).await?;

    match result {
        Ok(object) => {
            let key_handle =
                register_object_handle(ctx_mgr, &ctx_id, CkObjectHandle(object.0)).await;
            Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
                ck_rv: CkRv::OK.0,
                key_handle,
            }))
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::DeriveKeyResponse {
            ck_rv: error.0,
            key_handle: 0,
        })),
    }
}

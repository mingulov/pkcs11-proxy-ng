use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::CkRv;

use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::convert_template;
use super::super::service_utils::{
    ck_rv_only, register_object_handle, resolve_session, resolve_session_and_object, spawn_backend,
};

pub(super) async fn create_object(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::CreateObjectRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CreateObjectResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::CreateObjectResponse {
                ck_rv: error.0,
                object_handle: 0,
            }));
        }
    };

    let template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::CreateObjectResponse {
                ck_rv: error,
                object_handle: 0,
            }));
        }
    };

    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.create_object(session, &template)).await?;

    match result {
        Ok(object) => Ok(Response::new(pkcs11_proxy_ng_proto::CreateObjectResponse {
            ck_rv: CkRv::OK.0,
            object_handle: register_object_handle(ctx_mgr, &ctx_id, object).await,
        })),
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::CreateObjectResponse {
            ck_rv: error.0,
            object_handle: 0,
        })),
    }
}

pub(super) async fn copy_object(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::CopyObjectRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CopyObjectResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, object) =
        match resolve_session_and_object(ctx_mgr, &ctx_id, req.session_handle, req.object_handle)
            .await
        {
            Ok(handles) => handles,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::CopyObjectResponse {
                    ck_rv: error.0,
                    new_object_handle: 0,
                }));
            }
        };

    let template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::CopyObjectResponse {
                ck_rv: error,
                new_object_handle: 0,
            }));
        }
    };

    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.copy_object(session, object, &template)).await?;

    match result {
        Ok(object) => Ok(Response::new(pkcs11_proxy_ng_proto::CopyObjectResponse {
            ck_rv: CkRv::OK.0,
            new_object_handle: register_object_handle(ctx_mgr, &ctx_id, object).await,
        })),
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::CopyObjectResponse {
            ck_rv: error.0,
            new_object_handle: 0,
        })),
    }
}

pub(super) async fn destroy_object(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::DestroyObjectRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DestroyObjectResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, object) =
        match resolve_session_and_object(ctx_mgr, &ctx_id, req.session_handle, req.object_handle)
            .await
        {
            Ok(handles) => handles,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::DestroyObjectResponse {
                    ck_rv: error.0,
                }));
            }
        };

    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.destroy_object(session, object)).await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::DestroyObjectResponse { ck_rv: ck_rv_only(result) }))
}

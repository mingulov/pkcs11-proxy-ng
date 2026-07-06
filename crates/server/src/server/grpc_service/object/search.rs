use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_types::CkRv;

use super::super::super::context_manager::ClientContextId;
use super::super::HandlerContext;
use super::super::convert_template;
use super::super::service_utils::{
    ck_rv_only, register_object_handles, resolve_session, spawn_backend,
};

pub(super) async fn find_objects_init(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::FindObjectsInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::FindObjectsInitResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(&ctx.context_manager, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsInitResponse {
                ck_rv: error.0,
            }));
        }
    };

    let template = match convert_template(&req.template) {
        Ok(template) => template,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsInitResponse {
                ck_rv: error,
            }));
        }
    };

    let backend = ctx.backend.clone();
    let result = spawn_backend(move || backend.find_objects_init(session, &template)).await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsInitResponse { ck_rv: ck_rv_only(result) }))
}

pub(super) async fn find_objects(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::FindObjectsRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::FindObjectsResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(&ctx.context_manager, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
                ck_rv: error.0,
                object_handles: vec![],
            }));
        }
    };

    let max_count = req.max_object_count;
    let backend = ctx.backend.clone();
    let result = spawn_backend(move || backend.find_objects(session, max_count)).await?;

    match result {
        Ok(backend_objects) => {
            if crate::server::resilience::observe_find_result(backend_objects.len()) {
                // COUNT ONLY — never log the labels/IDs/values (design V15/D9 redaction).
                tracing::warn!(
                    object_count = backend_objects.len(),
                    "pathological object population: C_FindObjects result exceeds resilience threshold"
                );
            }
            match register_object_handles(&ctx.context_manager, &ctx_id, &backend_objects).await {
                Some(object_handles) => {
                    Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
                        ck_rv: CkRv::OK.0,
                        object_handles,
                    }))
                }
                None => Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
                    ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
                    object_handles: vec![],
                })),
            }
        }
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsResponse {
            ck_rv: error.0,
            object_handles: vec![],
        })),
    }
}

pub(super) async fn find_objects_final(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::FindObjectsFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::FindObjectsFinalResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(&ctx.context_manager, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsFinalResponse {
                ck_rv: error.0,
            }));
        }
    };

    let backend = ctx.backend.clone();
    let result = spawn_backend(move || backend.find_objects_final(session)).await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::FindObjectsFinalResponse { ck_rv: ck_rv_only(result) }))
}

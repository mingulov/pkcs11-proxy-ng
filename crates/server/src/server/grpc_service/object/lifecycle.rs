use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_types::CkRv;

use super::super::super::context_manager::ClientContextId;
use super::super::super::handle_map::VirtualHandle;
use super::super::HandlerContext;
use super::super::convert_template;
use super::super::service_utils::{
    ck_rv_only, register_session_object_handle, resolve_session, resolve_session_and_object,
    spawn_backend, template_declares_token_object,
};

pub(super) async fn create_object(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::CreateObjectRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CreateObjectResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(&ctx.context_manager, &ctx_id, req.session_handle).await {
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

    // Classify before the template is moved into the backend call: a session
    // object's handle is evicted when its session closes; a token object's
    // handle persists across sessions (B2).
    let is_token_object = template_declares_token_object(&template);
    let virtual_session = VirtualHandle(req.session_handle);
    let backend = ctx.backend.clone();
    let result = spawn_backend(move || backend.create_object(session, &template)).await?;

    match result {
        Ok(object) => Ok(Response::new(pkcs11_proxy_ng_proto::CreateObjectResponse {
            ck_rv: CkRv::OK.0,
            object_handle: register_session_object_handle(
                &ctx.context_manager,
                &ctx_id,
                virtual_session,
                object,
                is_token_object,
            )
            .await,
        })),
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::CreateObjectResponse {
            ck_rv: error.0,
            object_handle: 0,
        })),
    }
}

pub(super) async fn copy_object(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::CopyObjectRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::CopyObjectResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, object) = match resolve_session_and_object(
        &ctx.context_manager,
        &ctx_id,
        req.session_handle,
        req.object_handle,
    )
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

    // A copied object is a session object unless its template marks CKA_TOKEN (B2).
    let is_token = template_declares_token_object(&template);
    let virtual_session = VirtualHandle(req.session_handle);
    let backend = ctx.backend.clone();
    let result = spawn_backend(move || backend.copy_object(session, object, &template)).await?;

    match result {
        Ok(object) => Ok(Response::new(pkcs11_proxy_ng_proto::CopyObjectResponse {
            ck_rv: CkRv::OK.0,
            new_object_handle: register_session_object_handle(
                &ctx.context_manager,
                &ctx_id,
                virtual_session,
                object,
                is_token,
            )
            .await,
        })),
        Err(error) => Ok(Response::new(pkcs11_proxy_ng_proto::CopyObjectResponse {
            ck_rv: error.0,
            new_object_handle: 0,
        })),
    }
}

pub(super) async fn destroy_object(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DestroyObjectRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DestroyObjectResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, object) = match resolve_session_and_object(
        &ctx.context_manager,
        &ctx_id,
        req.session_handle,
        req.object_handle,
    )
    .await
    {
        Ok(handles) => handles,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DestroyObjectResponse {
                ck_rv: error.0,
            }));
        }
    };

    let backend = ctx.backend.clone();
    let result = spawn_backend(move || backend.destroy_object(session, object)).await?;

    // On successful destroy, evict the virtual->backend mapping so a recycled
    // backend object number can never alias this now-stale handle (B2).
    if result.is_ok() {
        let virtual_object = VirtualHandle(req.object_handle);
        let _ = ctx
            .context_manager
            .get_context(&ctx_id, |client_ctx| client_ctx.object_handles.remove(virtual_object))
            .await;
    }

    Ok(Response::new(pkcs11_proxy_ng_proto::DestroyObjectResponse { ck_rv: ck_rv_only(result) }))
}

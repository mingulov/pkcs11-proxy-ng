use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::{CkObjectHandle, CkRv, CkSessionHandle};

use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::super::handle_map::{BackendHandle, VirtualHandle};
use super::super::ck_result_to_rv;
use super::super::service_utils::{ck_rv_only, spawn_backend};

async fn resolve_state_handles(
    ctx_mgr: &Arc<ContextManager>,
    ctx_id: &ClientContextId,
    session_handle: u64,
    encryption_key_handle: u64,
    authentication_key_handle: u64,
) -> Result<(CkSessionHandle, CkObjectHandle, CkObjectHandle), CkRv> {
    let resolved: Option<(Option<BackendHandle>, Option<BackendHandle>, Option<BackendHandle>)> =
        ctx_mgr
            .get_context(ctx_id, |ctx| {
                (
                    ctx.session_handles.resolve(VirtualHandle(session_handle)),
                    ctx.object_handles.resolve(VirtualHandle(encryption_key_handle)),
                    ctx.object_handles.resolve(VirtualHandle(authentication_key_handle)),
                )
            })
            .await;

    let Some((session, encryption_key, authentication_key)) = resolved else {
        return Err(CkRv::CRYPTOKI_NOT_INITIALIZED);
    };

    let backend_session = session.ok_or(CkRv::SESSION_HANDLE_INVALID)?;
    let encryption_key =
        encryption_key.map(|handle| CkObjectHandle(handle.0)).unwrap_or(CkObjectHandle(0));
    let authentication_key =
        authentication_key.map(|handle| CkObjectHandle(handle.0)).unwrap_or(CkObjectHandle(0));

    Ok((CkSessionHandle(backend_session.0), encryption_key, authentication_key))
}

pub(super) async fn get_operation_state(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GetOperationStateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetOperationStateResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session =
        match super::super::service_utils::resolve_session(ctx_mgr, &ctx_id, req.session_handle)
            .await
        {
            Ok(session) => session,
            Err(error) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::GetOperationStateResponse {
                    ck_rv: error.0,
                    operation_state: vec![],
                }));
            }
        };

    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.get_operation_state(session)).await?;
    let (ck_rv, operation_state) = ck_result_to_rv(result);

    Ok(Response::new(pkcs11_proxy_ng_proto::GetOperationStateResponse {
        ck_rv,
        operation_state: operation_state.unwrap_or_default(),
    }))
}

pub(super) async fn set_operation_state(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SetOperationStateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SetOperationStateResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, encryption_key, authentication_key) = match resolve_state_handles(
        ctx_mgr,
        &ctx_id,
        req.session_handle,
        req.encryption_key_handle,
        req.authentication_key_handle,
    )
    .await
    {
        Ok(handles) => handles,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SetOperationStateResponse {
                ck_rv: error.0,
            }));
        }
    };

    let operation_state = req.operation_state;
    let backend = backend_ref.clone();
    let result = spawn_backend(move || {
        backend.set_operation_state(session, &operation_state, encryption_key, authentication_key)
    })
    .await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::SetOperationStateResponse {
        ck_rv: ck_rv_only(result),
    }))
}

use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::service_utils::{context_exists, spawn_backend};

pub(super) async fn get_info(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GetInfoRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GetInfoResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    if !context_exists(ctx_mgr, &ctx_id).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::GetInfoResponse {
            ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
            info: None,
        }));
    }

    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.get_info()).await?;
    let (ck_rv, info) = match result {
        Ok(info) => (CkRv::OK.0, Some(pkcs11_proxy_ng_proto::CryptokiInfo::from(&info))),
        Err(error) => (error.0, None),
    };
    Ok(Response::new(pkcs11_proxy_ng_proto::GetInfoResponse { ck_rv, info }))
}

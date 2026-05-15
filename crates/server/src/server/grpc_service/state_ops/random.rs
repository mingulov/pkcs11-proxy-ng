use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;

use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::ck_result_to_rv;
use super::super::service_utils::{ck_rv_only, resolve_session, spawn_backend};

pub(super) async fn generate_random(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::GenerateRandomRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::GenerateRandomResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::GenerateRandomResponse {
                ck_rv: error.0,
                random_data: vec![],
            }));
        }
    };

    let len = req.length;
    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.generate_random(session, len)).await?;
    let (ck_rv, random_data) = ck_result_to_rv(result);

    Ok(Response::new(pkcs11_proxy_ng_proto::GenerateRandomResponse {
        ck_rv,
        random_data: random_data.unwrap_or_default(),
    }))
}

pub(super) async fn seed_random(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SeedRandomRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SeedRandomResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SeedRandomResponse { ck_rv: error.0 }));
        }
    };

    let seed = req.seed;
    let backend = backend_ref.clone();
    let result = spawn_backend(move || backend.seed_random(session, &seed)).await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::SeedRandomResponse { ck_rv: ck_rv_only(result) }))
}
